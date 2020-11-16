import tkinter as tk
from tkinter import *
from tkinter import font as tkfont
import tkinter.messagebox
import re
import pyodbc 
import os
import smtplib
import imghdr
from email.message import EmailMessage
import hashlib
import secrets
import msvcrt
import time
import threading
import multiprocessing

class Comunication_LTD(tk.Tk):

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.shared_data = { 
            'email': tk.StringVar(),
            'password': tk.StringVar(),
            'code' : tk.StringVar(),
        }

        self.title_font = tkfont.Font(family='Arial Black', size=15, weight="bold")

        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        # List of frames to switch between
        self.frames = {}
        for F in (WelcomePage, Login, Register,ForgotPassword,ChangePassword,System,NewClient,Confirm):
            page_name = F.__name__
            frame = F(parent=container, controller=self)
            self.frames[page_name] = frame

            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("WelcomePage")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()


class WelcomePage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.configure(bg='skyblue')
        myFont = tk.font.Font(family='Arial Black', size=10, weight='bold')
        label = tk.Label(self, text="Welcome to Comunication_LTD", font=controller.title_font,bg="skyblue",fg="grey30")
        label.pack(side="top", fill="x", pady=10)

        button1 = tk.Button(self, text="Register",height="4",width="20",fg="grey30",bg="skyblue",borderwidth="3",
                            command=lambda: controller.show_frame("Register"))
        label1  = tk.Label(self,bg="skyblue")
        button2 = tk.Button(self, text="Login",height="4",width="20",fg="grey30",bg="skyblue",borderwidth="3",
                            command=lambda: controller.show_frame("Login"))
        button1['font'] = myFont
        button2['font'] = myFont
        button1.pack()
        label1.pack()
        button2.pack()


class Register(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.configure(bg='skyblue')
        myFont = tk.font.Font(family='Arial Black', size=10, weight='bold')
        label = tk.Label(self, text="REGISTER", font=controller.title_font,bg="skyblue",fg="grey30")
        label.pack(side="top", fill="x", pady=10)

        # Email label and text entry box
        emailLabel = Label(self, text="Enter Email",bg="skyblue",fg="grey30")
        emailLabel['font'] = myFont
        emailEntry = Entry(self, textvariable=self.controller.shared_data["email"])
        emailLabel.pack()
        emailEntry.pack()
        
        # Password label and password entry box
        passwordLabel = Label(self,text="Enter Password",bg="skyblue",fg="grey30")
        password = StringVar()
        passwordEntry = Entry(self, textvariable=password, show='*')
        passwordLabel['font'] = myFont
        passwordLabel.pack()
        passwordEntry.pack()

        # Re-password label and password entry box
        repasswordLabel = Label(self,text="Re-enter password",bg="skyblue",fg="grey30")
        repassword = StringVar()
        repasswordEntry = Entry(self, textvariable=repassword, show='*')
        repasswordLabel['font'] = myFont
        repasswordLabel.pack()
        repasswordEntry.pack()

        button = tk.Button(self, text="Register",fg="grey30",bg="skyblue",borderwidth="3",
                           command= lambda: OnClick())
        button1 = tk.Button(self, text="Already Registered ? Click to Login",fg="grey30",bg="skyblue",borderwidth="3",command=lambda: controller.show_frame("Login"))
        button['font'] = myFont
        button1['font'] = myFont
        button.pack()
        button1.pack()

        # Validating all the entered information by the user
        def OnClick():
            validEmail = False
            validPassword = False
            validRepassword = False
            hashed_password = ""
            if CheckEmail(validEmail) and CheckPassword(validPassword) and CheckRePassword(validRepassword):

                # DB connection setup
                conn = pyodbc.connect('Driver={SQL Server};'
                'Server=DESKTOP-L2SGLHO\SQLEXPRESS;'
                'Database=Users;'
                'Trusted_Connection=yes;')

                cursor = conn.cursor()
                # INSERT query
                query = 'INSERT INTO my_users (Email, Password) VALUES (?, ?);'

                # Hashing
                hashed_password = make_hash(password.get())

                # Commiting all the data into DB
                values = (self.controller.shared_data["email"].get(), hashed_password)
                cursor.execute(query, values)
                conn.commit()
                
                cursor.close()
                conn.close()

                emailEntry.delete(0, END)
                passwordEntry.delete(0, END)
                repasswordEntry.delete(0,END)

                controller.show_frame("Login")
        
        def make_hash(password):
            return hashlib.sha256(str.encode(password)).hexdigest()
        
        # Error windows 
        def WrongEmailFormat(state):
            if state == False:
                tkinter.messagebox.showerror("Error", "Invalid Email.")
        
        def WrongPasswordFormat(state):
            if state == False:
                tkinter.messagebox.showerror("Error", "Please enter a valid password.")
        
        def WrongRepasswordFormat(state):
            if state == False:
                tk.messagebox.showerror("Error", "Re-password you entered doesn't match the password.")
        
        # Checking if the mail/password/repassword are by the requested format and if not it will pop an error window

        def CheckEmail(validEmail):
            cMail = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
            if(re.search(cMail,self.controller.shared_data["email"].get())):  
                pass
            else:  
                WrongEmailFormat(False)
                
            # DB connection setup
            conn = pyodbc.connect('Driver={SQL Server};'
            'Server=DESKTOP-L2SGLHO\SQLEXPRESS;'
            'Database=Users;'
            'Trusted_Connection=yes;')

            cursor = conn.cursor()
            query = "SELECT * FROM my_users WHERE Email = ?"
            cursor.execute(query, self.controller.shared_data["email"].get())
            result = cursor.fetchall()

            if result:
                tkinter.messagebox.showerror("Error", "User already exists.")
                validEmail = False
            else:
                validEmail = True
            return validEmail

        def CheckPassword(validPassword):
            cPassword = "R@m@_f0rtu9e$"
            flag = 0
            while True:   
                if (len(password.get())<3): 
                    flag = -1
                    break
                elif not re.search("[a-z]", password.get()): 
                    flag = -1
                    break
                elif not re.search("[A-Z]", password.get()): 
                    flag = -1
                    break
                elif not re.search("[0-9]", password.get()): 
                    flag = -1
                    break
                elif not re.search("[_@$]", password.get()): 
                    flag = -1
                    break
                elif re.search("\s", password.get()): 
                    flag = -1
                    break
                else: 
                    flag = 0
                    validPassword = True
                    break
            if flag == -1: 
                WrongPasswordFormat(False)
                validPassword = False
            return validPassword
        
        def CheckRePassword(validRepassword):
            if password.get() != repassword.get():
                WrongRepasswordFormat(False)
                validRepassword = False
            else:
                validRepassword = True
            return validRepassword
                    

class Login(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.configure(bg='skyblue')
        countin = 0
        myFont = tk.font.Font(family='Arial Black', size=10, weight='bold')
        label = tk.Label(self, text="LOGIN", font=controller.title_font,bg="skyblue",fg="grey30")
        label.pack(side="top", fill="x", pady=10)

        #email label and text entry box
        emailLabel = Label(self, text="Enter Email",bg="skyblue",fg="grey30")
        emailLabel['font'] = myFont
        emailEntry = Entry(self, textvariable=self.controller.shared_data["email"])
        emailLabel.pack()
        emailEntry.pack()
        
        #password label and password entry box
        passwordLabel = Label(self,text="Enter Password",bg="skyblue",fg="grey30")
        password = StringVar()
        passwordEntry = Entry(self, textvariable=password, show='*')
        passwordLabel['font'] = myFont
        passwordLabel.pack()
        passwordEntry.pack()

        button = tk.Button(self, text="Login",fg="grey30",bg="skyblue",borderwidth="3",
                           command=lambda: OnClick())
        button1 = tk.Button(self, text="Forgot My Password",fg="grey30",bg="skyblue",borderwidth="3",
                           command=lambda: controller.show_frame("ForgotPassword"))
        button2 = tk.Button(self, text="Not a memeber yet ? Click to Register",fg="grey30",bg="skyblue",borderwidth="3", command=lambda: controller.show_frame("Register"))
        button['font'] = myFont
        button1['font'] = myFont
        button2['font'] = myFont
        button.pack()
        button1.pack()
        button2.pack()

        def OnClick():
            nonlocal countin
            # DB connection setup
            conn = pyodbc.connect('Driver={SQL Server};'
            'Server=DESKTOP-L2SGLHO\SQLEXPRESS;'
            'Database=Users;'
            'Trusted_Connection=yes;')

            cursor = conn.cursor()

            # SELECT query
            query = 'SELECT * FROM my_users WHERE Email = ? AND Password = ?;'

            # Hashing
            hashed_password = make_hash(password.get())
            # Commiting all the data into DB
            values = (self.controller.shared_data["email"].get(), hashed_password)
            cursor.execute(query, values)

            result = cursor.fetchall()
            if result:
                emailEntry.delete(0, END)
                passwordEntry.delete(0, END)
                controller.show_frame("System")
            else:
                tkinter.messagebox.showerror("Error", "Please enter an existing account.")
                # Need to create a timer when the user tries more than 3 times
                '''countin+=1'''
            conn.commit()
            cursor.close()
            conn.close()
        
        
        def make_hash(password):
            return hashlib.sha256(str.encode(password)).hexdigest()


class ChangePassword(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.configure(bg='skyblue')
        myFont = tk.font.Font(family='Arial Black', size=10, weight='bold')
        label = tk.Label(self, text="Change Password", font=controller.title_font,bg="skyblue",fg="grey30")
        label.pack(side="top", fill="x", pady=10)

        # Password label and password entry box
        passwordLabel = Label(self,text="Enter Password",bg="skyblue",fg="grey30")
        password = StringVar()
        passwordEntry = Entry(self, textvariable=password, show='*')
        passwordLabel['font'] = myFont
        passwordLabel.pack()
        passwordEntry.pack()

        # Re-password label and password entry box
        repasswordLabel = Label(self,text="Re-enter password",bg="skyblue",fg="grey30")
        repassword = StringVar()
        repasswordEntry = Entry(self, textvariable=repassword, show='*')
        repasswordLabel['font'] = myFont
        repasswordLabel.pack()
        repasswordEntry.pack()

        button = tk.Button(self, text="Change Password",fg="grey30",bg="skyblue",borderwidth="3",
                           command=lambda: OnClick())
        label1  = tk.Label(self,bg="skyblue")
        label1.pack()                   
        button['font'] = myFont
        button.pack()

        def OnClick():
            validPassword = False
            validRepassword = False
            hashed_password = ""
            if CheckPassword(validPassword) and CheckRePassword(validRepassword):
                # DB connection setup
                conn = pyodbc.connect('Driver={SQL Server};'
                'Server=DESKTOP-L2SGLHO\SQLEXPRESS;'
                'Database=Users;'
                'Trusted_Connection=yes;')

                cursor = conn.cursor()
                # INSERT query
                query = 'UPDATE my_users SET Password = ? WHERE email = ?;'

                # Hashing
                hashed_password = make_hash(password.get())
                values = (hashed_password,self.controller.shared_data["email"].get())

                # Commiting all the data into DB
                cursor.execute(query, values)
                conn.commit()
                
                cursor.close()
                conn.close()
                controller.show_frame("Login")
        
        def make_hash(password):
            return hashlib.sha256(str.encode(password)).hexdigest()

        def WrongPasswordFormat(state):
            if state == False:
                tkinter.messagebox.showerror("Error", "Please enter a valid password.")
        
        def WrongRepasswordFormat(state):
            if state == False:
                tk.messagebox.showerror("Error", "Re-password you entered doesn't match the password.")

        def CheckPassword(validPassword):
            cPassword = "R@m@_f0rtu9e$"
            flag = 0
            while True:   
                if (len(password.get())<3): 
                    flag = -1
                    break
                elif not re.search("[a-z]", password.get()): 
                    flag = -1
                    break
                elif not re.search("[A-Z]", password.get()): 
                    flag = -1
                    break
                elif not re.search("[0-9]", password.get()): 
                    flag = -1
                    break
                elif not re.search("[_@$]", password.get()): 
                    flag = -1
                    break
                elif re.search("\s", password.get()): 
                    flag = -1
                    break
                else: 
                    flag = 0
                    validPassword = True
                    break
            if flag == -1: 
                WrongPasswordFormat(False)
                validPassword = False
            return validPassword
        
        def CheckRePassword(validRepassword):
            if password.get() != repassword.get():
                WrongRepasswordFormat(False)
                validRepassword = False
            else:
                validRepassword = True
            return validRepassword


class ForgotPassword(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.configure(bg='skyblue')
        myFont = tk.font.Font(family='Arial Black', size=10, weight='bold')
        label = tk.Label(self, text="Forgot Password", font=controller.title_font,bg="skyblue",fg="grey30")
        label.pack(side="top", fill="x", pady=10)

        #email label and text entry box
        emailLabel = Label(self, text="Enter Email",bg="skyblue",fg="grey30")
        emailLabel['font'] = myFont
        emailEntry = Entry(self, textvariable=self.controller.shared_data["email"])
        emailLabel.pack()
        emailEntry.pack()

        button = tk.Button(self, text="Send Me",fg="grey30",bg="skyblue",borderwidth="3",
                           command=lambda: OnClick())
        button2 = tk.Button(self, text="Not a memeber yet ? Click to Register",fg="grey30",bg="skyblue",borderwidth="3", command=lambda: controller.show_frame("Register"))

        label1  = tk.Label(self,bg="skyblue")
        button['font'] = myFont
        button2['font'] = myFont
        label1.pack()
        button.pack()
        button2.pack()
        
        def OnClick():
    
            # DB connection setup
            conn = pyodbc.connect('Driver={SQL Server};'
            'Server=DESKTOP-L2SGLHO\SQLEXPRESS;'
            'Database=Users;'
            'Trusted_Connection=yes;')

            cursor = conn.cursor()

            # SELECT query
            query = 'SELECT * FROM my_users WHERE Email = ?;'

            # Commiting all the data into DB
            cursor.execute(query, self.controller.shared_data["email"].get())

            result = cursor.fetchall()
            if result:
                self.controller.shared_data['code'] = secrets.token_hex(16)
                msg = EmailMessage()
                msg['Subject'] = 'Recover Password Code'
                msg['From'] = 'dinsakedo@gmail.com'
                msg['To'] = self.controller.shared_data["email"].get()
                msg.set_content(self.controller.shared_data['code'])

                with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                    smtp.login('dinsakedo@gmail.com', 'tisfpvpkkwbiclzl')
                    smtp.send_message(msg)
                tkinter.messagebox.showinfo("Email Sent","Code sent to your email.")
                controller.show_frame("Confirm")
            else:
                tkinter.messagebox.showerror("Error", "Please enter an existing account.")
                # Need to create a timer when the user tries more than 3 times
                '''countin+=1'''
            conn.commit()
            cursor.close()
            conn.close()
            

class Confirm(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.configure(bg='skyblue')
        myFont = tk.font.Font(family='Arial Black', size=10, weight='bold')
        label = tk.Label(self, text="Confirmation", font=controller.title_font,bg="skyblue",fg="grey30")
        label.pack(side="top", fill="x", pady=10)
        
        #code label
        codeLabel = Label(self,text="Enter Code",bg="skyblue",fg="grey30")
        codeLabel['font'] = myFont
        code = StringVar()
        codeEntry = Entry(self, textvariable=code, show='*')
        codeLabel.pack()
        codeEntry.pack()

        button = tk.Button(self, text="Confirm",fg="grey30",bg="skyblue",borderwidth="3",
                           command=lambda: OnClick())
        button1 = tk.Button(self,text="Cancel",fg="grey30",bg="skyblue",borderwidth="3",
                           command=lambda: Cancel())
        label1  = tk.Label(self,bg="skyblue")
        text = Label(self,bg="skyblue",fg="grey30")
        button['font'] = myFont
        button1['font'] = myFont
        text['font'] = myFont
        label1.pack()
        button.pack()
        text.pack()
        button1.pack()

        def Countdown():
            my_timer = 30
            for _ in range(my_timer):
                my_timer = my_timer - 1
                time.sleep(1)
                text.config(text=my_timer)
        
        tmr = threading.Thread(target=Countdown)
        tmr.start()

        def OnClick():
            if self.controller.shared_data['code'] == code.get():
                controller.show_frame('ChangePassword')
            else:
                tkinter.messagebox.showerror("Error", "Please enter a valid code.")

        def Cancel():
            self.controller.shared_data['code'] = secrets.token_hex(16)
            controller.show_frame("ForgotPassword")


class System(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.configure(bg='skyblue')
        myFont = tk.font.Font(family='Arial Black', size=10, weight='bold')
        label = tk.Label(self, text="Welcome User123 !", font=controller.title_font,bg="skyblue",fg="grey30")
        label.pack(side="top", fill="x", pady=30)
        print(self.controller.shared_data["email"].get())
        
        button = tk.Button(self, text="Add new client",height="3",width="15",fg="grey30",bg="skyblue",borderwidth="3",
                           command=lambda: controller.show_frame("NewClient"))
        button1 = tk.Button(self, text="Logout",fg="grey30",bg="skyblue",borderwidth="3",
                           command=lambda: controller.show_frame("WelcomePage"))
        label1  = tk.Label(self,bg="skyblue")
        button['font'] = myFont
        button1['font'] = myFont
        button.pack()
        label1.pack()
        button1.pack()


class NewClient(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.configure(bg='skyblue')
        myFont = tk.font.Font(family='Arial Black', size=10, weight='bold')
        label = tk.Label(self, text="Create New Client", font=controller.title_font,bg="skyblue",fg="grey30")
        label.pack(side="top", fill="x", pady=10)

        # FirstName label and text entry box
        firstNameLabel = Label(self, text="First Name",bg="skyblue",fg="grey30")
        firstNameLabel['font'] = myFont
        firstName = StringVar()
        firstNameEntry = Entry(self, textvariable=firstName)
        firstNameLabel.pack()
        firstNameEntry.pack()
        
        # LastName label and password entry box
        lastNameLabel = Label(self,text="Last Name",bg="skyblue",fg="grey30")
        lastNameLabel['font'] = myFont
        lastName = StringVar()
        lastNameEntry = Entry(self, textvariable=lastName)
        lastNameLabel.pack()
        lastNameEntry.pack()

        # age label and password entry box
        ageLabel = Label(self,text="Age",bg="skyblue",fg="grey30")
        ageLabel['font'] = myFont
        age = StringVar()
        ageEntry = Entry(self, textvariable=age)
        ageLabel.pack()
        ageEntry.pack()

        # age label and password entry box
        cityLabel = Label(self,text="City",bg="skyblue",fg="grey30")
        cityLabel['font'] = myFont
        city = StringVar()
        cityEntry = Entry(self, textvariable=city,)
        cityLabel.pack()
        cityEntry.pack()

        button = tk.Button(self, text="Add new client",bg="skyblue",fg="grey30",
                           command=lambda: OnClick())
        button1 = tk.Button(self, text="Cancel",bg="skyblue",fg="grey30",
                           command=lambda: controller.show_frame("System"))
        button['font'] = myFont
        button1['font'] = myFont
        label1  = tk.Label(self,bg="skyblue")
        label1.pack() 
        button.pack()
        button1.pack()


        def OnClick():
            validFirstName = False
            validLastName = False
            validAge = False
            validCity = False
            if CheckFirstName(validFirstName) and CheckLastName(validLastName) and CheckAge(validAge) and CheckCity(validCity):

                # DB connection setup
                conn = pyodbc.connect('Driver={SQL Server};'
                'Server=DESKTOP-L2SGLHO\SQLEXPRESS;'
                'Database=Clients;'
                'Trusted_Connection=yes;')

                cursor = conn.cursor()

                # INSERT query
                query = 'INSERT INTO Clients (firstName, lastName, age, city) VALUES (?, ?, ?, ?);'

                # Commiting all the data into DB
                values = (firstName.get(),lastName.get(),age.get(),city.get())
                cursor.execute(query, values)
                conn.commit()
                cursor.execute('SELECT * FROM Clients')
                for row in cursor:
                    print(row)
                
                cursor.close()
                conn.close()

                controller.show_frame("System")
                print("You Registered !")

        def WrongFirstNameFormat(state):
            if state == False:
                tkinter.messagebox.showerror("Error", "Invalid First Name.")
        
        def WrongLastNameFormat(state):
            if state == False:
                tkinter.messagebox.showerror("Error", "Invalid Last Name.")
        
        def WrongAgeFormat(state):
            if state == False:
                tk.messagebox.showerror("Error", "Invalid Age")
        
        def WrongCityFormat(state):
            if state == False:
                tk.messagebox.showerror("Error", "Invalid City")


        def CheckFirstName(validFirstName):
            if(special_match(firstName.get())): 
                print(firstName.get())
                validFirstName = True
            else:  
                WrongFirstNameFormat(False)
                validFirstName = False

            return validFirstName

        def CheckLastName(validLastName):
            if(special_match(lastName.get())):  
                print(lastName.get())
                validLastName = True
            else:  
                WrongLastNameFormat(False)
                validLastName = False

            return validLastName

        def CheckAge(validAge):
            cAge = "^\d{1,2}$"
            if(re.search(cAge,age.get())):  
                print(age.get())
                validAge = True
            else:  
                WrongAgeFormat(False)
                validAge = False

            return validAge

        def CheckCity(validCity):
            if(special_match(city.get())):  
                print(city.get())
                validCity = True
            else:  
                WrongCityFormat(False)
                validCity = False

            return validCity

        def special_match(strg, search=re.compile(r'[^a-z.]').search):
            return bool(search(strg))



if __name__ == "__main__":
    app = Comunication_LTD()
    app.iconbitmap("icon.ico")
    app.title("Communication_LTD")
    app.geometry("400x400")
    app.mainloop()