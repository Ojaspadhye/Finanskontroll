from rest_framework import serializers
from Finance.models import Financial_Record
from datetime import datetime


class FinancialRecordSerializer(serializers.ModelSerializer):
    created_by_data = serializers.ReadOnlyField()
    created_by_authority = serializers.ReadOnlyField()

    class Meat:
        model = Financial_Record
        fields = ["id", "amount", "category", "note", "created_by_data", "created_by_authority"]


class CreateRecordSerializer(serializers.Serializer):
    amount = serializers.DecimalField(max_digits=32, decimal_places=2)
    category = serializers.CharField(max_length=20)
    note = serializers.CharField(max_length=250, allow_blank=True)
    transction_date = serializers.DateField()

    def validate(self, data):
        data["category"] = data["category"].lower().strip()

        amount = data["amount"]
        if amount < 0:
            raise serializers.ValidationError("Ammount cannot be zero")
        
        date = data["transction_data"]
        if date > datetime.now().date():
            raise serializers.ValidationError("Transction cannot be ahead in future")
        
        return data