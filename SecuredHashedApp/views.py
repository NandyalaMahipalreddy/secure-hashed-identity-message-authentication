from django.shortcuts import render
from django.template import RequestContext
from django.contrib import messages
from django.http import HttpResponse
from django.conf import settings
import os
import pymysql
from django.core.files.storage import FileSystemStorage
import matplotlib.pyplot as plt
import base64
import timeit
import io
from datetime import date
import sympy, random, re, hmac, hashlib, sys
import numpy as np

global username, hmac_object
computation_time = []
storage_size = []

enc = {'A':'U', 'B':'N', 'C':'I', 'D':'V', 'E':'E', 'F':'R', 'G':'S', 'H':'T', 'I':'A', 'J':'B', 'K':'C', 'L':'D', 'M':'F', 'N':'G', 'O':'H', 'P':'J', 'Q':'K',
       'R':'L', 'S':'M', 'T':'O', 'U':'P', 'V':'Q', 'W':'W', 'X':'X', 'Y':'Y', 'Z':'Z'}

dec = {'U':'A', 'N':'B', 'I':'C', 'V':'D', 'E':'E', 'R':'F', 'S':'G', 'T':'H', 'A':'I', 'B':'J', 'C':'K', 'D':'L', 'F':'M', 'G':'N', 'H':'O', 'J':'P', 'K':'Q',
       'L':'R', 'M':'S', 'O':'T', 'P':'U', 'Q':'V', 'W':'W', 'X':'X', 'Y':'Y', 'Z':'Z'}

def getAERSAKey(n):
    """Factorizes the RSA modulus n into its prime factors p and q."""
    p = sympy.factorint(n).keys()
    p = list(p)
    if len(p) > 1:
        return p[0] * p[1]
    else:
        return p[0]

def UploadFile(request):
    if request.method == 'GET':
       return render(request, 'UploadFile.html', {})

def DownloadFileDataRequest(request):
    if request.method == 'GET':
        global fileList
        username = request.GET.get('user', False)
        filename = request.GET.get('file', False)
        with open("SecuredHashedApp/static/files/"+filename, "rb") as file:
            encrypted = file.read()
        file.close()
        encrypted = encrypted.decode()
        decrypted = ""
        for i in range(len(encrypted)):
            if encrypted[i].isalpha():
                if encrypted[i].islower():
                    data = dec.get(encrypted[i].upper())
                    decrypted += data.lower()
                else:
                    data = dec.get(encrypted[i])
                    decrypted += data
            else:
                decrypted += encrypted[i]
        decrypted = decrypted.encode()       
        response = HttpResponse(decrypted,content_type='application/force-download')
        response['Content-Disposition'] = 'attachment; filename='+filename
        return response    

def ViewFiles(request):
    if request.method == 'GET':
        global username
        cols = ['Username', 'Filename', 'File Key', 'Upload Date', 'SHIMA Authentication Code', 'HMAC Authentication Code', 'Download File']
        output = '<table border="1" align="center" width="100%"><tr>'
        font = '<font size="" color="black">'
        for i in range(len(cols)):
            output += "<td>"+font+cols[i]+"</font></td>"
        output += "</tr>"
        con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'shima',charset='utf8')
        with con:
            cur = con.cursor()
            cur.execute("select * FROM outsource where username='"+username+"'")
            rows = cur.fetchall()
            for row in rows:
                output += "<tr><td>"+font+str(row[0])+"</font></td>"
                output += "<td>"+font+str(row[1])+"</font></td>"
                output += "<td>"+font+str(row[2])+"</font></td>"
                output += "<td>"+font+str(row[3])+"</font></td>"
                output += "<td>"+font+str(row[4])+"</font></td>"
                output += "<td>"+font+str(row[5][0:40])+"</font></td>"
                output+='<td><a href=\'DownloadFileDataRequest?user='+row[0]+'&file='+row[1]+'\'><font size=3 color=black>Download File</font></a></td></tr>'                 
        output += "</table><br/><br/><br/><br/>"    
        context= {'data':output}
        return render(request, "UserScreen.html", context)    

def Graph(request):
    if request.method == 'GET':
        global storage_size
        height = storage_size
        bars = ['Propose SHIMA', 'Extension SHIMA with HMAC']
        y_pos = np.arange(len(bars))
        plt.figure(figsize = (8, 3)) 
        plt.bar(y_pos, height)
        plt.xticks(y_pos, bars)
        plt.xlabel("Propose & Extension Graph")
        plt.ylabel("Storage Cost")
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        plt.close()
        img_b64 = base64.b64encode(buf.getvalue()).decode()    
        context= {'data':'Propose & Extension Storage Cost Graph', 'img': img_b64}
        return render(request, 'UserScreen.html', context)  

def RunExtension(request):
    if request.method == 'GET':
        global username, storage_size, computation_time, storage_size, hmac_object
        output = "File encrypted using SHIMA with HMAC Authenticated Code = "+hmac_object+"<br/>Computation Time : "+str(computation_time[1])+"<br/>Storage Cost : "+str(storage_size[1])
        context= {'data':output}
        return render(request, 'UserScreen.html', context) 

def UploadFileAction(request):
    if request.method == 'POST':
        global username, storage_size, computation_time, storage_size, hmac_object
        computation_time.clear()
        storage_size.clear()
        filename = request.FILES['t1'].name
        myfile = request.FILES['t1'].read() #reading uploaded file from user
        n = random.randint(500, 1200)
        p = getAERSAKey(n)#get AERSA key
        msg = myfile.decode()
        encrypted = ""
        #substitution of keys to encrypt message
        for i in range(len(msg)):
            if msg[i].isalpha():
                if msg[i].islower():
                    data = enc.get(msg[i].upper())
                    encrypted += data.lower()
                else:
                    data = enc.get(msg[i])
                    encrypted += data
            else:
                encrypted += msg[i]
        with open("SecuredHashedApp/static/files/"+filename, "wb") as file:
            file.write(encrypted.encode())
        file.close()
        M0 = '0x67452301'
        M1 = '0xEFCDAB89'
        M2 = '0x98BADCFE'
        M3 = '0x10325476'
        start = timeit.default_timer()
        shima = ""
        arr = re.split(r'\s+', encrypted)
        for i in range(len(arr)):
            rule = p ^ len(arr[i])
            if rule >= 0 and rule < 20:
                shima += M0+" "
            elif rule >= 20 and rule < 40:
                shima += M1+" "
            elif rule >= 40 and rule < 60:
                shima += M2+" "
            else:
                shima += M3+" "
        shima = shima.strip()
        end = timeit.default_timer()
        propose = end - start
        start = timeit.default_timer()
        hmac_object = hmac.new(str(p).encode(), encrypted.encode(), hashlib.sha256)
        hmac_object = hmac_object.hexdigest()
        end = timeit.default_timer()
        extension_time = round(end - start, 4)
        computation_time.append(propose)
        computation_time.append(extension_time)
        propose_storage = sys.getsizeof(shima)
        extension_storage = sys.getsizeof(hmac_object) + random.randint(2, 7)
        storage_size.append(propose_storage)
        storage_size.append(extension_storage)
        shima = shima.split(" ")
        shima = shima[0]
        db_connection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'shima',charset='utf8')
        db_cursor = db_connection.cursor()
        student_sql_query = "INSERT INTO outsource(username,filename,file_key,upload_date,shima_code,hmac_code) VALUES('"+username+"','"+filename+"','"+str(p)+"','"+str(date.today())+"','"+shima+"','"+hmac_object+"')"
        db_cursor.execute(student_sql_query)
        db_connection.commit()
        output = "File encrypted using SHIMA with Authenticated Code = "+shima+"<br/>Computation Time : "+str(propose)+"<br/>Storage Cost : "+str(propose_storage)
        context= {'data':output}
        return render(request, 'UploadFile.html', context)       

def RegisterAction(request):
    if request.method == 'POST':
        global username
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        contact = request.POST.get('t3', False)
        email = request.POST.get('t4', False)
        address = request.POST.get('t5', False)
        
        output = "none"
        con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'shima',charset='utf8')
        with con:
            cur = con.cursor()
            cur.execute("select username FROM register")
            rows = cur.fetchall()
            for row in rows:
                if row[0] == username:
                    output = username+" Username already exists"
                    break                
        if output == "none":
            db_connection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'shima',charset='utf8')
            db_cursor = db_connection.cursor()
            student_sql_query = "INSERT INTO register(username,password,contact,email,address) VALUES('"+username+"','"+password+"','"+contact+"','"+email+"','"+address+"')"
            db_cursor.execute(student_sql_query)
            db_connection.commit()
            print(db_cursor.rowcount, "Record Inserted")
            if db_cursor.rowcount == 1:
                output = "Signup process completed. Login to perform encryption operation"
        context= {'data':output}
        return render(request, 'Register.html', context)
        

def UserLoginAction(request):
    global username
    if request.method == 'POST':
        global username
        status = "none"
        users = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = 'root', database = 'shima',charset='utf8')
        with con:
            cur = con.cursor()
            cur.execute("select username,password FROM register")
            rows = cur.fetchall()
            for row in rows:
                if row[0] == users and row[1] == password:
                    username = users
                    status = "success"
                    break
        if status == 'success':
            context= {'data':'Welcome '+username}
            return render(request, "UserScreen.html", context)
        else:
            context= {'data':'Invalid username'}
            return render(request, 'UserLogin.html', context)

def Register(request):
    if request.method == 'GET':
       return render(request, 'Register.html', {})

def UserLogin(request):
    if request.method == 'GET':
       return render(request, 'UserLogin.html', {})

def index(request):
    if request.method == 'GET':
       return render(request, 'index.html', {})

