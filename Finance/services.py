from Finance.models import Financial_Record
from datetime import datetime, timedelta
from django.db import transaction
import logging

logger = logging.getLogger(__name__)

SCOPE_MAP = {
    "days": 7,
    "weeks": 4,
    "months": 30,
    "years": 365
}

def get_date_range(date_offset, date_scope):
    now = datetime.now().date()

    try:
        date_offset = int(date_offset)
    except (ValueError, TypeError):
        raise ValueError("date_offset should be an integer")
    
    if date_scope not in SCOPE_MAP:
        raise ValueError("date_scope must be 'days', 'weeks', 'months', or 'years'")
    
    if date_scope == "days":
        start_date = now - timedelta(days=date_offset)
    elif date_scope == "weeks":
        start_date = now - timedelta(weeks=date_offset)
    elif date_scope == "months":
        start_date = now - timedelta(days=30 * date_offset)
    elif date_scope == "years":
        start_date = now - timedelta(days=365 * date_offset)

    return start_date, now


def apply_filters(record, query_parameters):
    category = query_parameters.get("category")
    if category:
        record = record.filter(category__iexact=category)

    min_amount = query_parameters.get("min_amount")
    max_amount = query_parameters.get("max_amount")

    if min_amount:
        record = record.filter(amount__gte=min_amount)
    if max_amount:
        record = record.filter(amount__lte=max_amount)

    str_start_date = query_parameters.get("start_date")
    str_end_date = query_parameters.get("end_date")

    if str_start_date:
        start_date = datetime.strptime(str_start_date, "%Y-%m-%d").date()
        record = record.filter(transaction_date__gte=start_date)
    if str_end_date:
        end_date = datetime.strptime(str_end_date, "%Y-%m-%d").date()
        record = record.filter(transaction_date__lte=end_date)

    str_date = query_parameters.get("date")
    if str_date:
        exact_date = datetime.strptime(str_date, "%Y-%m-%d").date()
        record = record.filter(transaction_date=exact_date)

    date_offset = query_parameters.get("date_offset")
    date_scope = query_parameters.get("date_scope")

    if date_offset and date_scope:
        try:
            start_date, now = get_date_range(date_offset, date_scope)
            record = record.filter(transaction_date__gte=start_date, transaction_date__lte=now)
        except ValueError as e:
            raise ValueError(f"Date range error: {e}")

    return record


def get_records(requests):
    records = Financial_Record.objects.all()    
    request_parameters = requests.GET

    try:
        records = apply_filters(record=records, query_parameters=request_parameters)
    except ValueError:
        raise ValueError("No Records with such constraints")
    
    return records


def create_records_services(validated_data, user):
    if user.authority not in ["Admin", "Analyst"]:
        raise PermissionError("You dont have this level of ascess")

    amount = validated_data["amount"]
    category = validated_data["category"]
    note = validated_data.get("note", "")
    transaction_date = validated_data["transaction_date"]

    with transaction.atomic():
        record = Financial_Record.objects.create(
            amount=amount,
            category=category,
            note=note,
            transaction_date=transaction_date,
            created_by=user
        )
        record.save()
        logger.info(f"Financial record created | user={user.id} | category={category} | amount={amount}")

    return {"message": "Record Created"}


def update_record_service(validated_data, record):
    amount = validated_data["amount"]
    category = validated_data["category"]
    note = validated_data.get("note")
    transaction_date = validated_data["transaction_date"]

    update_data = {}

    if amount:
        record.amount = amount
        update_data["amount"] = amount

    if category:
        record.category = category
        update_data["category"] = category

    if note:
        record.note = note
        update_data["note"] = note

    if transaction_date:
        record.transaction_date = transaction_date
        update_data["transaction_date"] = transaction_date

    record.save()
    return update_data