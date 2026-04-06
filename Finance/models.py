from django.db import models
from uuid import uuid1

# Create your models here.
class Financial_Record(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid1, editable=False)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.CharField(max_length=20)
    note = models.CharField(max_length=250, blank=True)
    
    date_created = models.DateTimeField(auto_now_add=True)
    transaction_date = models.DateField()

    created_by = models.ForeignKey(
        "UserAuth.UserProfile",
        on_delete=models.SET_NULL,
        related_name="financial_records",
        null=True
    )

    @property
    def created_by_data(self):
        if self.created_by:
            return {"id": self.created_by.id, "username": self.created_by.username}
        return None
    
    @property
    def created_by_authority(self):
        if self.created_by:
            return self.created_by.authority
        return None


    class Meta:
        verbose_name="Financial_Record"
        verbose_name_plural = "Financial_Records"
        ordering = ["-transaction_date"]
