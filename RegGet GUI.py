from Registry import Registry
from datetime import datetime, timedelta
from tkinter import *
from tkinter import ttk
import hashlib
from scrollableFrame import ScrollableFrame


class MainGUI():
    def __init__(self):
        self.first_screen_file = "FirstScreen.png"
        self.file_screen = "FileEntry.png"
        self.menu_screen_file = "MainMenu.png"
        self.hash_screen_file = "HashScreen.png"
        self.SysInfoMenu = "SysInfoMenu.png"
        self.os_screen_file = "OSInfo.png"
        self.ctrl_file = "ControlSetScreen.png"
        self.timezone_file = "TimezoneScreen.png"
        self.NetScreen = "NetScreen.png"
        self.InterfaceScreen = "InterfaceScreen.png"
        self.accScreen = "AccScreen.png"
        self.extScreen = "ExtScreen.png"
        self.ManualScreen = "ManualScreen.png"
        self.FValScreen = "FValueSeperate.png"
        self.AnalyseScreen = "HexAnalyse.png"

        self.__MainWindow = Tk()
        self.__title = "RegGet"
        self.__screen_geometry = "1920x1080"
        self.CurrentFrame = None

        self.system_file = StringVar()
        self.software_file = StringVar()
        self.sam_file = StringVar()
        self.security_file = StringVar()
        self.ntuser_file = StringVar()

        self.software_reg = object
        self.system_reg = object
        self.sam_reg = object
        self.security_reg = object
        self.ntuser_reg = object

        self.hash_ls = []
        self.current_set = 0
        self.NicGUID = []
        self.chosen_interface = StringVar()
        self.NicDict = {}
        self.hex_string = StringVar()
        self.hex_error = ""

    def ClearWindow(self):
        window = self.__MainWindow
        _list = window.winfo_children()

        for item in _list:
            item.destroy()

    def CreateFrame(self, ImageFileName):
        menuScreen = self.__MainWindow

        frame = Frame(menuScreen, width=682, height=453, bg='#001636', )
        frame.pack(side=LEFT)

        background_label = ttk.Label(frame, text="")
        background_label.place(x=0, y=0)

        logo = PhotoImage(file=ImageFileName)
        background_label.config(image=logo)
        background_label.img = logo
        background_label.config(image=background_label.img)
        frame.place(x=26, y=235)
        return frame

    def DestroyFrame(self):
        self.CurrentFrame.destroy()

    def first_screen(self):
        self.ClearWindow()
        firstScreen = self.__MainWindow
        firstScreen.title(self.__title)
        firstScreen.geometry(self.__screen_geometry)

        firstScreen.attributes("-topmost", False)
        firstScreen.resizable(False, False)
        background = ttk.Label(firstScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.first_screen_file, master=firstScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        btnCont = ttk.Button(firstScreen, command=self.file_select, text="CONTINUE")
        btnCont.place(x=620, y=510)

        firstScreen.option_add('*tearOff', False)
        firstScreen.mainloop()

    def file_select(self):
        self.ClearWindow()
        fileScreen = self.__MainWindow
        fileScreen.title(self.__title)
        fileScreen.geometry(self.__screen_geometry)

        fileScreen.attributes("-topmost", False)
        fileScreen.resizable(False, False)
        background = ttk.Label(fileScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.file_screen, master=fileScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        samEntry = ttk.Entry(fileScreen, textvariable=self.sam_file)
        samEntry.place(x=805, y=270)

        softEntry = ttk.Entry(fileScreen, textvariable=self.software_file)
        softEntry.place(x=805, y=380)

        secEntry = ttk.Entry(fileScreen, textvariable=self.security_file)
        secEntry.place(x=805, y=490)

        sysEntry = ttk.Entry(fileScreen, textvariable=self.system_file)
        sysEntry.place(x=805, y=600)

        ntEntry = ttk.Entry(fileScreen, textvariable=self.ntuser_file)
        ntEntry.place(x=805, y=710)

        btnEnter = ttk.Button(fileScreen, text="Continue", command=self.main_menu)
        btnEnter.place(x=805, y=810)

    def main_menu(self):
        self.software_reg = Registry.Registry(self.software_file.get())
        self.system_reg = Registry.Registry(self.system_file.get())
        self.sam_reg = Registry.Registry(self.sam_file.get())
        self.security_reg = Registry.Registry(self.security_file.get())
        self.ntuser_reg = Registry.Registry(self.ntuser_file.get())

        self.ClearWindow()
        menuScreen = self.__MainWindow
        menuScreen.title(self.__title)
        menuScreen.geometry(self.__screen_geometry)

        menuScreen.attributes("-topmost", False)
        menuScreen.resizable(False, False)
        background = ttk.Label(menuScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.menu_screen_file, master=menuScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        btnSystem = ttk.Button(menuScreen, text="Analyse this", command=self.sys_info_menu)
        btnSystem.place(x=350, y=360)
        btnAcc = ttk.Button(menuScreen, text="Analyse this", command=self.account_info)
        btnAcc.place(x=350, y=790)
        btnDev = ttk.Button(menuScreen, text="Analyse this", command=self.external_devices)
        btnDev.place(x=1423, y=360)
        btnMan = ttk.Button(menuScreen, text="Analyse this", command=self.manual_decoder)
        btnMan.place(x=1423, y=839)

        btnHash = ttk.Button(menuScreen, text="Get file hashes", command=self.hash_screen)
        btnHash.place(x=843, y=265)

    def hash_screen(self):
        self.ClearWindow()
        hashScreen = self.__MainWindow
        hashScreen.title(self.__title)
        hashScreen.geometry(self.__screen_geometry)

        hashScreen.attributes("-topmost", False)
        hashScreen.resizable(False, False)
        background = ttk.Label(hashScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.hash_screen_file, master=hashScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        files = [self.sam_file.get(), self.system_file.get(), self.security_file.get(), self.software_file.get(),
                 self.ntuser_file.get()]

        xcord = 840
        ycord = 226

        for file in files:
            f = open(file, "rb")
            fbytes = f.read()
            md5_hash = hashlib.md5(fbytes)
            digested_hash = md5_hash.hexdigest().upper()
            self.hash_ls.append(digested_hash)
            ttk.Label(hashScreen, text=digested_hash, background="#00C2CB", font=("Roboto", 20)).place(x=xcord, y=ycord)
            ycord += 140

        btnExport = ttk.Button(hashScreen, text="Export hashes", command=self.hash_export)
        btnExport.place(x=861, y=970)

        btnBack = ttk.Button(hashScreen, text=" Back ", command=self.main_menu)
        btnBack.place(x=861, y=895)

    def hash_export(self):
        with open("Registry hashes.txt", "w") as f:
            f.write("MD5 hashes\n")
            f.write("----------\n")
            f.write(f"SAM hash: {self.hash_ls[0]}\n")
            f.write(f"System hash: {self.hash_ls[1]}\n")
            f.write(f"Security hash: {self.hash_ls[2]}\n")
            f.write(f"Software hash: {self.hash_ls[3]}\n")
            f.write(f"NTUSER.DAT hash: {self.hash_ls[4]}\n")

    def sys_info_menu(self):
        self.ClearWindow()
        sysMenu = self.__MainWindow
        sysMenu.title(self.__title)
        sysMenu.geometry(self.__screen_geometry)

        sysMenu.attributes("-topmost", False)
        sysMenu.resizable(False, False)
        background = ttk.Label(sysMenu, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.SysInfoMenu, master=sysMenu)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        btnOS = ttk.Button(sysMenu, text="Analyse this", command=self.os_information)
        btnOS.place(x=447, y=340)
        btnCtrl = ttk.Button(sysMenu, text="Analyse this", command=self.control_set_info)
        btnCtrl.place(x=867, y=340)
        btnTime = ttk.Button(sysMenu, text="Analyse this", command=self.timezone_info)
        btnTime.place(x=1287, y=340)
        btnNet = ttk.Button(sysMenu, text="Analyse this", command=self.network_info)
        btnNet.place(x=867, y=743)

        btnBack = ttk.Button(sysMenu, text=" Back ", command=self.main_menu)
        btnBack.place(x=70, y=940)

    def os_information(self):
        self.ClearWindow()
        osScreen = self.__MainWindow
        osScreen.title(self.__title)
        osScreen.geometry(self.__screen_geometry)

        osScreen.attributes("-topmost", False)
        osScreen.resizable(False, False)
        background = ttk.Label(osScreen, text="")
        background.place(x=0, y=0)

        current_ver_key = self.software_reg.open("Microsoft\\Windows NT\\CurrentVersion")
        os_type = current_ver_key["ProductName"].value()

        pattern = r"(?P<Win10>Windows 10)|(?P<Win8>Windows 8)|(?P<Win7>Windows 7)|(?P<WinVS>Windows Vista)|(?P<WinServer>Windows Server)|(?P<WinXP>Windows XP)"
        regex = re.compile(pattern)
        m = regex.search(os_type)
        if m is not None:
            if m.group(1) is not None:
                file_name = "Win10Screen.png"
            elif m.group(2) is not None:
                file_name = "Win8Screen.png"
            elif m.group(3) is not None:
                file_name = "Win7Screen.png"
            elif m.group(4) is not None:
                file_name = "OSInfo.png"
            elif m.group(5) is not None:
                file_name = "WinServerScreen.png"
            elif m.group(6) is not None:
                file_name = "WinXPScreen.png"
        else:
            file_name = "OSInfo.png"

        logo = PhotoImage(file=file_name, master=osScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        lblOS = ttk.Label(osScreen, text=os_type, background="#00C2CB", font=("Roboto", 20))
        lblOS.place(x=1056, y=297)

        try:
            dos_install_date = current_ver_key['InstallDate']
            converted_date = datetime.fromtimestamp(dos_install_date.value())
            lblInstall = ttk.Label(osScreen, text=converted_date, background="#00C2CB", font=("Roboto", 20))
            lblInstall.place(x=1056, y=506)

        except:
            pass

        try:
            service_pack = current_ver_key["CSDVersion"].value()
            lblService = ttk.Label(osScreen, text=service_pack, background="#00C2CB", font=("Roboto", 20))
            lblService.place(x=1056, y=623)
        except:
            pass

        try:
            organisation = current_ver_key["RegisteredOrganization"].value()
            lblOrg = ttk.Label(osScreen, text=organisation, background="#00C2CB", font=("Roboto", 20))
            lblOrg.place(x=1056, y=735)
        except:
            pass

        try:
            owner = current_ver_key["RegisteredOwner"].value()
            lblOwner = ttk.Label(osScreen, text=owner, background="#00C2CB", font=("Roboto", 20))
            lblOwner.place(x=1056, y=859)
        except:
            pass

        try:
            computer_name = self.system_reg.open("ControlSet001\\Control\\ComputerName\\ComputerName")
            lblName = ttk.Label(osScreen, text=computer_name['ComputerName'].value(), background="#00C2CB",
                                font=("Roboto", 20))
            lblName.place(x=1056, y=402)
        except:
            pass

        btnBack = ttk.Button(osScreen, text=" Back ", command=self.sys_info_menu)
        btnBack.place(x=70, y=940)

    def control_set_info(self):
        self.ClearWindow()
        ctrlScreen = self.__MainWindow
        ctrlScreen.title(self.__title)
        ctrlScreen.geometry(self.__screen_geometry)

        ctrlScreen.attributes("-topmost", False)
        ctrlScreen.resizable(False, False)
        background = ttk.Label(ctrlScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.ctrl_file, master=ctrlScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        control_path = self.system_reg.open("Select")
        ctrl_set = control_path['Current'].value()
        self.current_set = f"ControlSet00{ctrl_set}"

        current = control_path['Current'].value()
        default = control_path['Default'].value()
        last = control_path['LastKnownGood'].value()

        lblCurrent = ttk.Label(ctrlScreen, text=current, background="#00C2CB", font=("Roboto", 20))
        lblCurrent.place(x=980, y=370)
        lblDefault = ttk.Label(ctrlScreen, text=default, background="#00C2CB", font=("Roboto", 20))
        lblDefault.place(x=980, y=560)
        lblLast = ttk.Label(ctrlScreen, text=last, background="#00C2CB", font=("Roboto", 20))
        lblLast.place(x=980, y=740)

        btnBack = ttk.Button(ctrlScreen, text=" Back ", command=self.sys_info_menu)
        btnBack.place(x=980, y=940)

    def timezone_info(self):
        self.ClearWindow()
        timeScreen = self.__MainWindow
        timeScreen.title(self.__title)
        timeScreen.geometry(self.__screen_geometry)

        timeScreen.attributes("-topmost", False)
        timeScreen.resizable(False, False)
        background = ttk.Label(timeScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.timezone_file, master=timeScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        timezone_path = self.system_reg.open("ControlSet001\\Control\\TimeZoneInformation")
        bias = timezone_path['Bias'].value()
        standard = timezone_path['StandardName'].value()
        daylight = timezone_path['DaylightName'].value()

        lblBias = ttk.Label(timeScreen, text=bias, background="#00C2CB", font=("Roboto", 20))
        lblBias.place(x=1070, y=452)
        lblStandard = ttk.Label(timeScreen, text=standard, background="#00C2CB", font=("Roboto", 20))
        lblStandard.place(x=1070, y=220)
        lblDaylight = ttk.Label(timeScreen, text=daylight, background="#00C2CB", font=("Roboto", 20))
        lblDaylight.place(x=1070, y=335)

        btnBack = ttk.Button(timeScreen, text=" Back ", command=self.sys_info_menu)
        btnBack.place(x=70, y=940)

    def network_info(self):
        self.ClearWindow()
        netScreen = self.__MainWindow
        netScreen.title(self.__title)
        netScreen.geometry(self.__screen_geometry)

        netScreen.attributes("-topmost", False)
        netScreen.resizable(False, False)
        background = ttk.Label(netScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.NetScreen, master=netScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        card_subkeys = []
        network_key = self.software_reg.open("Microsoft\\Windows NT\\CurrentVersion\\NetworkCards")
        for subkey in network_key.subkeys():
            card_subkeys.append(subkey.name())

        NicNames = []
        self.NicDict = {}
        self.NicGUID = []

        for net_card in card_subkeys:
            nic = self.software_reg.open(f"Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\{net_card}")
            desc = (nic['Description'].value())
            name = (nic['ServiceName'].value())
            self.NicDict.update({name: desc})

        lblTotal = ttk.Label(netScreen, text=len(NicNames), background="#00C2CB", font=("Roboto", 30))
        lblTotal.place(x=810, y=305)

        ycord = 410
        count = 1

        for x, y in self.NicDict.items():
            ttk.Label(netScreen, text=y, background="#00C2CB", font=("Roboto", 20)).place(x=600, y=ycord)
            ttk.Label(netScreen, text=count, background="#00C2CB", font=("Roboto", 20)).place(x=520, y=ycord)
            ycord += 110
            ttk.Label(netScreen, text=x, background="#00C2CB", font=("Roboto", 20)).place(x=600, y=ycord)
            count += 1
            ycord += 100

        btnAnalyse = ttk.Button(netScreen, text='Analyse', command=self.interface_analysis)
        btnAnalyse.place(x=741, y=882)

        btnBack = ttk.Button(netScreen, text=" Back ", command=self.sys_info_menu)
        btnBack.place(x=70, y=940)
        # {DA9B4496-D4E7-4ACA-87C1-77D319D6FCC0}

    def interface_analysis(self):
        self.ClearWindow()
        intScreen = self.__MainWindow
        intScreen.title(self.__title)
        intScreen.geometry(self.__screen_geometry)

        intScreen.attributes("-topmost", False)
        intScreen.resizable(False, False)
        background = ttk.Label(intScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.InterfaceScreen, master=intScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        # {0F4E56D0-36AB-4E2F-A566-BD22F16293B2}

        for x, y in self.NicDict.items():
            xcord = 420
            ycord = 333
            intXcord = 642

            interface_reg = self.system_reg.open(f"ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\{x}")
            dhcp_addr = interface_reg['DhcpIPAddress'].value()
            ip_static = interface_reg['IPAddress'].value()
            gateway = interface_reg['Dhcpdefaultgateway'].value()
            lease_time = interface_reg['LeaseObtainedTime'].value()
            converted_date = datetime.fromtimestamp(lease_time)
            dhcp_domain = interface_reg['DhcpDomain'].value()

            if ip_static == "0.0.0.0":
                static = "No"
            else:
                static = "Yes"

            lblInterface = ttk.Label(intScreen, text=y, background="#00C2CB", font=("Roboto", 16))
            lblInterface.place(x=intXcord, y=234)
            intXcord += 714

            lblDhcp = ttk.Label(intScreen, text=dhcp_addr, background="#00C2CB", font=("Roboto", 20))
            lblDhcp.place(x=xcord, y=ycord)

            ycord += 109

            lblStatic = ttk.Label(intScreen, text=static, background="#00C2CB", font=("Roboto", 20))
            lblStatic.place(x=xcord, y=ycord)

            ycord += 109

            lblGateway = ttk.Label(intScreen, text=gateway[0], background="#00C2CB", font=("Roboto", 20))
            lblGateway.place(x=xcord, y=ycord)

            ycord += 109

            lblTime = ttk.Label(intScreen, text=converted_date, background="#00C2CB", font=("Roboto", 20))
            lblTime.place(x=xcord, y=ycord)

            ycord += 109

            lblDomain = ttk.Label(intScreen, text=dhcp_domain, background="#00C2CB", font=("Roboto", 20))
            lblDomain.place(x=xcord, y=ycord)

            xcord += 525

        btnBack = ttk.Button(intScreen, text=" Back ", command=self.sys_info_menu)
        btnBack.place(x=70, y=1000)

    def account_info(self):
        self.ClearWindow()
        accScreen = self.__MainWindow
        accScreen.title(self.__title)
        accScreen.geometry(self.__screen_geometry)

        accScreen.attributes("-topmost", False)
        accScreen.resizable(False, False)
        background = ttk.Label(accScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.accScreen, master=accScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        username_key = self.sam_reg.open("SAM\\Domains\\Account\\Users\\Names")
        user_accounts = []

        for subkey in username_key.subkeys():
            user_accounts.append(subkey.name())

        lblTotal = ttk.Label(accScreen, text=f"Total accounts: {len(user_accounts)}", background="#00C2CB",
                             font=("Roboto", 20))
        lblTotal.place(x=704, y=168)

        # 707 256
        ycord = 256
        for acc in user_accounts:
            ttk.Label(accScreen, text=f"Account found: {acc}", background="#00C2CB", font=("Roboto", 20)).place(x=707,
                                                                                                                y=ycord)
            ycord += 80

        btnBack = ttk.Button(accScreen, text=" Back ", command=self.main_menu)
        btnBack.place(x=70, y=940)

        lblHelp = ttk.Label(accScreen, text="Use the manual decoder for more\nin-depth account analysis",
                            background="#00C2CB", font=("Roboto", 20))
        lblHelp.place(x=35, y=570)

    def external_devices(self):
        self.ClearWindow()
        extScreen = self.__MainWindow
        extScreen.title(self.__title)
        extScreen.geometry(self.__screen_geometry)

        extScreen.attributes("-topmost", False)
        extScreen.resizable(False, False)
        background = ttk.Label(extScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.extScreen, master=extScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        usbstor = self.system_reg.open(f"{self.current_set}\\Enum\\USBSTOR")

        vendor_keys = []
        vendor_dict = {}
        for subkey in usbstor.subkeys():
            vendor_keys.append(subkey.name())

        lblTotal = ttk.Label(extScreen, text=len(usbstor.subkeys()), background="#00C2CB",
                             font=("Roboto", 26))
        lblTotal.place(x=1737, y=128)

        for usb in vendor_keys:
            vendor = self.system_reg.open(f"{self.current_set}\\Enum\\USBSTOR\\{usb}")
            for sub in vendor.subkeys():
                vendor_dict.update({usb: sub.name()})

        ycord = 220

        lblHeader = ttk.Label(extScreen, text="Unfriendly name\t\t\t\tDescription\tGUID\t\t\t\t\tName",
                              background="#00C2CB", font=("Roboto", 16))
        lblHeader.place(x=100, y=185)

        for key, val in vendor_dict.items():
            usb_device = self.system_reg.open(f"ControlSet001\\Enum\\USBSTOR\\{key}\\{val}")
            description = usb_device['DeviceDesc'].value()
            guid = usb_device['ClassGUID'].value()
            name = usb_device['FriendlyName'].value()
            unfriendlyName = str(key).replace("Disk&Ven_", "")

            ttk.Label(extScreen, text=f"{unfriendlyName}\t\t{description}\t\t{guid}\t{name}",
                      background="#00C2CB", font=("Roboto", 16)).place(x=100, y=ycord)

            ycord += 100

        btnBack = ttk.Button(extScreen, text=" Back ", command=self.main_menu)
        btnBack.place(x=1467, y=34)

    def manual_decoder(self):
        self.ClearWindow()
        manScreen = self.__MainWindow
        manScreen.title(self.__title)
        manScreen.geometry(self.__screen_geometry)

        manScreen.attributes("-topmost", False)
        manScreen.resizable(False, False)
        background = ttk.Label(manScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.ManualScreen, master=manScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        if self.hex_error == "The hex you entered is not the full F value!":
            lblError = ttk.Label(manScreen, text=self.hex_error, background="#00C2CB", font=("Roboto", 20))
            lblError.place(x=720, y=613)

        EntryHex = ttk.Entry(manScreen, textvariable=self.hex_string, width=172)
        EntryHex.place(x=530, y=360)

        btnDecode = ttk.Button(manScreen, text=" Decode ", command=self.decode_hex)
        btnDecode.place(x=750, y=480)

    def decode_hex(self):
        self.ClearWindow()
        decodeScreen = self.__MainWindow
        decodeScreen.title(self.__title)
        decodeScreen.geometry(self.__screen_geometry)

        decodeScreen.attributes("-topmost", False)
        decodeScreen.resizable(False, False)
        background = ttk.Label(decodeScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.FValScreen, master=decodeScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        if len(self.hex_string.get()) < 239:
            self.hex_error = "The hex you entered is not the full F value!"
            self.manual_decoder()

        else:
            hex_list = self.hex_string.get().split('-')

            last_login = self.endian_flip(hex_list[8:16])
            pass_reset = self.endian_flip(hex_list[24:32])
            expiry_date = self.endian_flip(hex_list[32:40])
            failed_login = self.endian_flip(hex_list[40:48])
            rid = self.endian_flip(hex_list[48:52])
            acc_status = hex_list[56]
            country_code = self.endian_flip(hex_list[60:62])
            invalid_count = self.endian_flip(hex_list[64:66])
            login_count = self.endian_flip(hex_list[66:68])

            lblLastLogin = ttk.Label(decodeScreen, text=self.list_joiner(last_login), background="#00C2CB",
                                     font=("Roboto", 20))
            lblLastLogin.place(x=674, y=190)

            lblReset = ttk.Label(decodeScreen, text=self.list_joiner(pass_reset), background="#00C2CB",
                                 font=("Roboto", 20))
            lblReset.place(x=674, y=290)

            lblExpiry = ttk.Label(decodeScreen, text=self.list_joiner(expiry_date), background="#00C2CB",
                                  font=("Roboto", 20))
            lblExpiry.place(x=674, y=390)

            lblFailed = ttk.Label(decodeScreen, text=self.list_joiner(failed_login), background="#00C2CB",
                                  font=("Roboto", 20))
            lblFailed.place(x=674, y=490)

            lblRid = ttk.Label(decodeScreen, text=self.list_joiner(rid), background="#00C2CB", font=("Roboto", 20))
            lblRid.place(x=674, y=590)

            lblAcc = ttk.Label(decodeScreen, text=self.list_joiner(acc_status), background="#00C2CB",
                               font=("Roboto", 20))
            lblAcc.place(x=674, y=690)

            lblCountry = ttk.Label(decodeScreen, text=self.list_joiner(country_code), background="#00C2CB",
                                  font=("Roboto", 20))
            lblCountry.place(x=674, y=790)

            lblCountry = ttk.Label(decodeScreen, text=self.list_joiner(invalid_count), background="#00C2CB",
                                   font=("Roboto", 20))
            lblCountry.place(x=674, y=890)

            lblCountry = ttk.Label(decodeScreen, text=self.list_joiner(login_count), background="#00C2CB",
                                   font=("Roboto", 20))
            lblCountry.place(x=674, y=990)

            btnAnalyse = ttk.Button(decodeScreen, text="Decode hex values", command=self.hex_analysis)
            btnAnalyse.place(x=1400, y=190)

    def hex_analysis(self):
        self.ClearWindow()
        hexScreen = self.__MainWindow
        hexScreen.title(self.__title)
        hexScreen.geometry(self.__screen_geometry)

        hexScreen.attributes("-topmost", False)
        hexScreen.resizable(False, False)
        background = ttk.Label(hexScreen, text="")
        background.place(x=0, y=0)

        logo = PhotoImage(file=self.AnalyseScreen, master=hexScreen)
        background.config(image=logo)
        background.img = logo
        background.config(image=background.img)

        hex_list = self.hex_string.get().split('-')

        last_login = self.endian_flip(hex_list[8:16])
        pass_reset = self.endian_flip(hex_list[24:32])
        expiry_date = self.endian_flip(hex_list[32:40])
        failed_login = self.endian_flip(hex_list[40:48])
        rid = self.endian_flip(hex_list[48:52])
        acc_status = hex_list[56]
        country_code = self.endian_flip(hex_list[60:62])
        invalid_count = self.endian_flip(hex_list[64:66])
        login_count = self.endian_flip(hex_list[66:68])

        date_time_values = [self.list_joiner(last_login), self.list_joiner(pass_reset), self.list_joiner(expiry_date),
                            self.list_joiner(failed_login)]
        integer_values = [self.list_joiner(rid), self.list_joiner(invalid_count), self.list_joiner(login_count)]

        decoded_integers = []
        for v in integer_values:
            decoded_integers.append(int(v, 16))

        status = ""
        if acc_status[0] == "0":
            status = status + "Account active and "
        else:
            status = status + "Account inactive and "
        if acc_status[1] == "0":
            status = status + "Password required"
        else:
            status = status + "Password not set"

        if int(decoded_integers[0]) < 1000:
            decodedRID = f"{decoded_integers[0]} (System account)"
        else:
            decodedRID = f"{decoded_integers[0]} (User account)"

        DecodedInvalidCount = decoded_integers[1]
        DecodedLoginCount = decoded_integers[2]

        if self.list_joiner(country_code) == "0000":
            DecodedCountry = "Default"
        elif self.list_joiner(country_code) == "0001":
            DecodedCountry = "US"
        elif self.list_joiner(country_code) == "0002":
            DecodedCountry = "Canada"

        converted_timestamps = []
        for ts in date_time_values:
            if ts == "7FFFFFFFFFFFFFFF":
                converted_timestamps.append("N/A")
            else:
                us = int(ts, 16) / 10
                converted_timestamps.append(datetime(1601, 1, 1) + timedelta(microseconds=us))

        DecodedLastLogin = converted_timestamps[0]
        DecodedReset = converted_timestamps[1]
        DecodedExpiry = converted_timestamps[2]
        DecodedLastFailed = converted_timestamps[3]

        lblLastLogin = ttk.Label(hexScreen, text=DecodedLastLogin, background="#00C2CB",
                                 font=("Roboto", 20))
        lblLastLogin.place(x=674, y=190)

        lblReset = ttk.Label(hexScreen, text=DecodedReset, background="#00C2CB",
                             font=("Roboto", 20))
        lblReset.place(x=674, y=290)

        lblExpiry = ttk.Label(hexScreen, text=DecodedExpiry, background="#00C2CB",
                              font=("Roboto", 20))
        lblExpiry.place(x=674, y=390)

        lblFailed = ttk.Label(hexScreen, text=DecodedLastFailed, background="#00C2CB",
                              font=("Roboto", 20))
        lblFailed.place(x=674, y=490)

        lblRid = ttk.Label(hexScreen, text=decodedRID, background="#00C2CB", font=("Roboto", 20))
        lblRid.place(x=674, y=590)

        lblAcc = ttk.Label(hexScreen, text=status, background="#00C2CB",
                           font=("Roboto", 20))
        lblAcc.place(x=674, y=690)

        lblCountry = ttk.Label(hexScreen, text=DecodedCountry, background="#00C2CB",
                               font=("Roboto", 20))
        lblCountry.place(x=674, y=790)

        lblCountry = ttk.Label(hexScreen, text=DecodedInvalidCount, background="#00C2CB",
                               font=("Roboto", 20))
        lblCountry.place(x=674, y=890)

        lblCountry = ttk.Label(hexScreen, text=DecodedLoginCount, background="#00C2CB",
                               font=("Roboto", 20))
        lblCountry.place(x=674, y=990)

        btnBack = ttk.Button(hexScreen, text=" Back ", command=self.manual_decoder)
        btnBack.place(x=1529, y=55)

    def list_joiner(self, ls):
        val = ""
        for i in ls:
            val = val + i

        return val

    def endian_flip(self, ls):
        count = 0
        for i in ls:
            t = ls.pop()
            ls.insert(count, t)
            count += 1
        return ls


c = MainGUI()
c.first_screen()
