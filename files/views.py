import mimetypes
from rest_framework.views import APIView
from rest_framework.response import Response
from django.http import FileResponse, JsonResponse, Http404
from rest_framework.permissions import IsAuthenticated
from django.conf import settings

from users.permissions import IsAdminUser, IsRegularUser
from .models import EncryptedFile, FileShare, SecureLink, User
from .utils import encrypt_file, decrypt_file
from datetime import datetime, timedelta
import os

class UserFilesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        user_files = EncryptedFile.objects.filter(owner=user).values("id", "filename", "created_at")
        return Response({"files": list(user_files)}, status=200)

class FileUploadView(APIView):
    permission_classes = [IsRegularUser | IsAdminUser]

    def post(self, request):
        uploaded_file = request.FILES.get("file")
        if not uploaded_file:
            return Response({"error": "No file uploaded"}, status=400)

        # Encrypt file content
        encrypted_content = encrypt_file(uploaded_file.read())
        file_path = os.path.join(settings.MEDIA_ROOT, "encrypted_files", uploaded_file.name)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)  # Ensure directory exists
        with open(file_path, "wb") as f:
            f.write(encrypted_content)

        # Save metadata in EncryptedFile model
        encrypted_file = EncryptedFile.objects.create(
            owner=request.user,
            file=f"encrypted_files/{uploaded_file.name}",  # Relative path
            filename=uploaded_file.name,
        )

        return Response({
            "message": "File uploaded and encrypted successfully.",
            "file_id": encrypted_file.id,
        }, status=201)
    

class FileDownloadView(APIView):
    permission_classes = [IsRegularUser | IsAdminUser]

    def get(self, request, file_id):
        try:
            # Get the file object
            file_obj = EncryptedFile.objects.get(id=file_id, owner=request.user)
            
            # Path to the encrypted file
            file_path = os.path.join(settings.MEDIA_ROOT, file_obj.file.name)
            
            # Check if file exists
            if not os.path.exists(file_path):
                raise Http404("File not found")

            # Read and decrypt the file content
            with open(file_path, "rb") as encrypted_file:
                encrypted_content = encrypted_file.read()
                decrypted_content = decrypt_file(encrypted_content)
            
            # Serve the file as an attachment
            mime_type, _ = mimetypes.guess_type(file_obj.filename)
            response = FileResponse(
                iter([decrypted_content]),
                content_type=mime_type or "application/octet-stream",
            )
            response["Content-Disposition"] = f"attachment; filename={file_obj.filename}"
            return response

        except EncryptedFile.DoesNotExist:
            return Response({"error": "File not found or access denied."}, status=404)

        except Exception as e:
            return Response({"error": str(e)}, status=500)


class ShareFileView(APIView):
    permission_classes = [IsRegularUser | IsAdminUser]

    def post(self, request):
        file_id = request.data.get("file_id")
        shared_with_username = request.data.get("shared_with")
        permission = request.data.get("permission", "view")  # Default to "view"
        expiration_hours = request.data.get("expires_in", 24)

        try:
            file = EncryptedFile.objects.get(id=file_id, owner=request.user)
            shared_with = User.objects.get(username=shared_with_username)

            expires_at = datetime.now() + timedelta(hours=expiration_hours)
            FileShare.objects.create(
                file=file,
                shared_with=shared_with,
                permission=permission,
                expires_at=expires_at,
            )

            return Response({"message": "File shared successfully."}, status=201)
        except EncryptedFile.DoesNotExist:
            return Response({"error": "File not found or you do not own it."}, status=404)
        except User.DoesNotExist:
            return Response({"error": "User to share with does not exist."}, status=404)


class GenerateSecureLinkView(APIView):
    permission_classes = [IsRegularUser | IsAdminUser]

    def post(self, request):
        file_id = request.data.get("file_id")
        expiration_hours = request.data.get("expires_in", 24)

        try:
            file = EncryptedFile.objects.get(id=file_id, owner=request.user)
            expires_at = datetime.now() + timedelta(hours=expiration_hours)
            secure_link = SecureLink.objects.create(file=file, expires_at=expires_at)

            return Response({
                "secure_link": f"{request.build_absolute_uri('/files/secure-link/')}{secure_link.link_id}"
            })
        except EncryptedFile.DoesNotExist:
            return Response({"error": "File not found or you do not own it."}, status=404)
    

class AccessSecureLinkView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, link_id):
        try:
            # Check if secure link is valid and not expired
            secure_link = SecureLink.objects.get(link_id=link_id, expires_at__gte=datetime.now())
            file = secure_link.file

            # Verify the requesting user has access to the file
            is_shared = FileShare.objects.filter(
                file=file,
                shared_with=request.user,
                expires_at__gte=datetime.now()
            ).exists()

            if not is_shared:
                return Response({"error": "You do not have permission to access this file."}, status=403)

            # Path to the encrypted file
            file_path = os.path.join(settings.MEDIA_ROOT, file.file.name)
            if not os.path.exists(file_path):
                raise Http404("File not found")

            # Decrypt and serve the file
            with open(file_path, "rb") as encrypted_file:
                encrypted_content = encrypted_file.read()
                decrypted_content = decrypt_file(encrypted_content)

            mime_type, _ = mimetypes.guess_type(file.filename)
            response = FileResponse(
                iter([decrypted_content]),
                content_type=mime_type or "application/octet-stream",
            )
            response["Content-Disposition"] = f"attachment; filename={file.filename}"
            return response
        except SecureLink.DoesNotExist:
            return Response({"error": "Invalid or expired link."}, status=404)


