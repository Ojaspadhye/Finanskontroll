from django.core.exceptions import PermissionDenied
from functools import wraps


def role_requirements(allowed_roles=[]):
    
    def decorator(view_function):
        
        @wraps(view_function)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_active or request.user.authority == "Lobby":
                raise PermissionDenied("Access Denied")
            
            if request.user.authority not in allowed_roles:
                raise PermissionDenied("Access Denied")
            
            return view_function(request, *args, **kwargs)
            
        return _wrapped_view
    
    return decorator