from django.urls import path

from . import views

urlpatterns = [path("index.html", views.index, name="index"),
	             path("UserLogin.html", views.UserLogin, name="UserLogin"),
		     path("Register.html", views.Register, name="Register"),
		     path("RegisterAction", views.RegisterAction, name="RegisterAction"),
		     path("UserLoginAction", views.UserLoginAction, name="UserLoginAction"),
		     path("UploadFile.html", views.UploadFile, name="UploadFile"),
		     path("UploadFileAction", views.UploadFileAction, name="UploadFileAction"),
		     path("ViewFiles", views.ViewFiles, name="ViewFiles"),
		     path("Graph", views.Graph, name="Graph"),
		     path("RunExtension", views.RunExtension, name="RunExtension"),
		     path("DownloadFileDataRequest", views.DownloadFileDataRequest, name="DownloadFileDataRequest"),
		    ]