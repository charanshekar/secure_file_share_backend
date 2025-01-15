from rest_framework.permissions import BasePermission

class IsAdminUser(BasePermission):
    """Permission for Admin users."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.groups.filter(name='Admin').exists()


class IsRegularUser(BasePermission):
    """Permission for Regular users."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.groups.filter(name='Regular User').exists()


class IsGuestUser(BasePermission):
    """Permission for Guests."""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.groups.filter(name='Guest').exists()
