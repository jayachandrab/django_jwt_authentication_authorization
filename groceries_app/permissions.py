from rest_framework.permissions import BasePermission

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        print("=======in is admin =====",request.user.is_authenticated,request.user.role.lower())
        return request.user.is_authenticated and request.user.role.lower() == 'admin'

class IsManager(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role.lower() == 'manager'

class IsAssistant(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role.lower() == 'assistant'

class IsAuthenticatedAndHasAnyRole(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role.lower() in ['admin', 'manager', 'assistant']
