from django.shortcuts import render
from decorators import role_requirements
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, throttle_classes
#from Finance.throtteling import 
from Finance.models import Financial_Record
from rest_framework.permissions import IsAuthenticated
from Finance.serializers import FinancialRecordSerializer, CreateRecordSerializer
from Finance.services import get_records, create_records_services, update_record_service
import logging
from datetime import datetime
import asyncio
from asgiref.sync import sync_to_async
from Finance.paginations import FinancialRecordPagination

# Create your views here.

logger = logging.getLogger(__name__)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
@role_requirements(allowed_roles=["Admin", "Viewer", "Analyst"])
def request_records_views(request):
    records = get_records(request)

    pagination = FinancialRecordPagination()
    pagination_record = pagination.pagination_record(records, request)

    serializer = FinancialRecordSerializer(pagination_record, many=True)
    return pagination.get_paginated_response(serializer.data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
@role_requirements(allowed_roles=["Admin", "Analyst"])
def create_records_views(request):
    serializer = CreateRecordSerializer(data=request.data, context={"request": request})
    serializer.is_valid(raise_exception=True)

    response = create_records_services(serializer.validated_data)

    return response



@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
@role_requirements(allowed_roles=["Admin"])
def delete_records_views(request, record_id):
    record = Financial_Record.objects.filter(id__iexact=record_id).first()
    if not record:
        return Response(
            {"error": "Financial record not found"},
            status=status.HTTP_404_NOT_FOUND
        )
    
    user = request.user
    logger.info(f"Admin: {user.username} | deleted {record.id} | on={datetime.now()}")
    
    record.delete()

    return Response(
        {"message": f"Financial record {record.id} deleted successfully"},
        status=status.HTTP_200_OK
    )


@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
@role_requirements(allowed_roles=["Admin"])
def update_record_views(request, record_id):
    record = Financial_Record.objects.filter(id__iexact=record_id).first()
    if not record:
        return Response(
            {"error": "Financial record not found"},
            status=status.HTTP_404_NOT_FOUND
        )

    serializer = FinancialRecordSerializer(instance=record, data=request.data, partial=True)
    serializer.is_valid(raise_exception=True)

    record_update = update_record_service(validated_data=serializer.validated_data, record=record)

    logger.info(f"Admin: {request.user.username} | updated record: {record_id} | at {datetime.now()}")
    return Response(record_update)


