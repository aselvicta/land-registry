import hashlib
import json
import time
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q
from django.db import IntegrityError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from .models import LandRecord
from .audit_log import log_action

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.load_from_database()

    def load_from_database(self):
        # Clear existing chain and reinitialize with database records
        self.chain = []
        records = LandRecord.objects.all().order_by('timestamp')
        if not records.exists():
            self.create_block(proof=1, previous_hash='0')
            return
        previous_block = None
        for i, record in enumerate(records, 1):
            plot_details = f"{record.plot_number}, {record.district}, {record.region}, {record.size}" + (
                f", Title Deed #{record.title_deed_number}" if record.title_deed_number else ""
            )
            if not previous_block:
                previous_block = self.create_block(proof=1, previous_hash='0')
            block = {
                'index': i,
                'timestamp': record.timestamp.timestamp(),
                'proof': 1,
                'previous_hash': self.hash_block(previous_block) if previous_block else '0',
                'records': [{
                    'owner_id': record.owner_id,
                    'plot_details': plot_details,
                    'record_hash': record.record_hash,
                    'signature': record.digital_signature,
                    'issuer': record.issuer.username
                }]
            }
            self.chain.append(block)
            previous_block = block

    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'proof': proof,
            'previous_hash': previous_hash,
            'records': []
        }
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def hash_block(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def add_record(self, owner_id, plot_details, issuer):
        record_data = f"{owner_id}:{plot_details}"
        record_hash = hashlib.sha256(record_data.encode()).hexdigest()
        signature = private_key.sign(
            record_hash.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        signature_hex = signature.hex()
        block = self.get_previous_block()
        block['records'].append({
            'owner_id': owner_id,
            'plot_details': plot_details,
            'record_hash': record_hash,
            'signature': signature_hex,
            'issuer': issuer
        })
        proof = 1
        previous_hash = self.hash_block(block)
        new_block = self.create_block(proof, previous_hash)
        return new_block, record_hash, signature_hex

    def verify_record(self, owner_id, plot_details):
        record_data = f"{owner_id}:{plot_details}"
        record_hash = hashlib.sha256(record_data.encode()).hexdigest()
        for block in self.chain:
            for record in block['records']:
                if record['owner_id'] == owner_id and record['record_hash'] == record_hash:
                    try:
                        public_key.verify(
                            bytes.fromhex(record['signature']),
                            record_hash.encode(),
                            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                            hashes.SHA256()
                        )
                        return True, "Record is valid"
                    except:
                        return False, "Invalid digital signature"
        return False, "Record not found or invalid"

blockchain = Blockchain()

@login_required
def admin_dashboard(request):
    if not request.user.is_staff:
        messages.error(request, "Access denied: Admins only")
        return redirect('verify_land')
    records = LandRecord.objects.all()
    # Applying filters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    owner_id_filter = request.GET.get('owner_id_filter')
    if start_date:
        records = records.filter(timestamp__gte=start_date)
    if end_date:
        records = records.filter(timestamp__lte=end_date)
    if owner_id_filter:
        records = records.filter(owner_id__icontains=owner_id_filter)
    return render(request, 'admin_dashboard.html', {'records': records})

@login_required
def register_land(request):
    if not request.user.is_staff:
        messages.error(request, "Access denied: Admins only")
        return redirect('verify_land')
    if request.method == 'POST':
        owner_id = request.POST.get('owner_id')
        plot_number = request.POST.get('plot_number')
        district = request.POST.get('district')
        region = request.POST.get('region')
        size = request.POST.get('size')
        title_deed_number = request.POST.get('title_deed_number', '')
        if owner_id and plot_number and district and region and size:
            if not request.session.get('mfa_verified', False):
                messages.error(request, "MFA verification required")
                return redirect('register_land')
            plot_details = f"{plot_number}, {district}, {region}, {size}" + (
                f", Title Deed #{title_deed_number}" if title_deed_number else ""
            )
            # Check 1: Preventing same owner from registering the same record
            existing_record = LandRecord.objects.filter(
                owner_id=owner_id,
                plot_number=plot_number,
                district=district,
                region=region,
                size=size,
                title_deed_number=title_deed_number or None
            ).exists()
            if existing_record:
                messages.error(request, "This land record already exists for this owner.")
                return render(request, 'register_land.html')
            
            # Check 2: Preventing different owners from registering the same land (plot_number, district, region)
            land_already_owned = LandRecord.objects.filter(
                plot_number=plot_number,
                district=district,
                region=region
            ).exclude(owner_id=owner_id).exists()
            if land_already_owned:
                messages.error(request, "This land is already registered under a different owner.")
                return render(request, 'register_land.html')
            
            try:
                block, record_hash, signature = blockchain.add_record(owner_id, plot_details, request.user.username)
                LandRecord.objects.create(
                    owner_id=owner_id,
                    plot_number=plot_number,
                    district=district,
                    region=region,
                    size=size,
                    title_deed_number=title_deed_number,
                    record_hash=record_hash,
                    digital_signature=signature,
                    issuer=request.user
                )
                # Rebuild blockchain to reflect new state
                blockchain.load_from_database()
                log_action(request.user, "Register Land Record", f"Owner ID: {owner_id}, Block: {block['index']}")
                messages.success(request, f"Land record registered in block {block['index']}")
                if request.POST.get('save_and_add_another'):
                    return redirect('register_land')
                return redirect('admin_dashboard')
            except IntegrityError:
                messages.error(request, "An error occurred. Duplicate record may exist.")
                return render(request, 'register_land.html')
        messages.error(request, "All required fields must be filled")
    request.session['mfa_verified'] = True
    return render(request, 'register_land.html')

def verify_land(request):
    if request.method == 'POST':
        owner_id = request.POST.get('owner_id')
        plot_number = request.POST.get('plot_number')
        district = request.POST.get('district')
        region = request.POST.get('region')
        size = request.POST.get('size')
        title_deed_number = request.POST.get('title_deed_number', '')
        if owner_id and plot_number and district and region and size:
            plot_details = f"{plot_number}, {district}, {region}, {size}" + (
                f", Title Deed #{title_deed_number}" if title_deed_number else ""
            )
            is_valid, message = blockchain.verify_record(owner_id, plot_details)
            log_action(None, "Verify Land Record", f"Owner ID: {owner_id}, Result: {message}")
            messages.info(request, message)
        else:
            messages.error(request, "All required fields must be filled")
    return render(request, 'verify_land.html')