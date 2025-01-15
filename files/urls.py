from django.urls import path
from .views import UserFilesView, FileUploadView, FileDownloadView, ShareFileView, GenerateSecureLinkView, AccessSecureLinkView

urlpatterns = [
    path("my-files/", UserFilesView.as_view(), name="user-files"),
    path("upload/", FileUploadView.as_view(), name="file-upload"),
    path("download/<int:file_id>/", FileDownloadView.as_view(), name="file-download"),
    path("share/", ShareFileView.as_view(), name="file-share"),
    path("generate-link/", GenerateSecureLinkView.as_view(), name="generate-secure-link"),
    path("secure-link/<uuid:link_id>/", AccessSecureLinkView.as_view(), name="access-secure-link"),
]
