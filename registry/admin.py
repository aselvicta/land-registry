from django.contrib import admin
from .models import LandRecord, AuditLog
from .views import blockchain, private_key
from .audit_log import log_action
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

class LandRecordAdmin(admin.ModelAdmin):
    list_display = ('owner_id', 'plot_number', 'district', 'region', 'size', 'title_deed_number', 'timestamp', 'issuer')
    search_fields = ('owner_id', 'plot_number', 'district', 'region')
    list_filter = ('timestamp', 'issuer')
    fields = ('owner_id', 'plot_number', 'district', 'region', 'size', 'title_deed_number')  # Show only these fields in form

    def save_model(self, request, obj, form, change):
        if not change:  # Only for new records
            plot_details = obj.get_plot_details()
            record_data = f"{obj.owner_id}:{plot_details}"
            record_hash = hashlib.sha256(record_data.encode()).hexdigest()
            signature = private_key.sign(
                record_hash.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            ).hex()
            block = blockchain.add_record(obj.owner_id, plot_details, request.user.username)[0]
            obj.record_hash = record_hash
            obj.digital_signature = signature
            obj.issuer = request.user
            log_action(request.user, "Register Land Record (Admin Panel)", f"Owner ID: {obj.owner_id}, Block: {block['index']}")
        super().save_model(request, obj, form, change)

admin.site.register(LandRecord, LandRecordAdmin)
admin.site.register(AuditLog)