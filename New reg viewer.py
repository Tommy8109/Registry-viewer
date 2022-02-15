from Registry import Registry
import hashlib
from datetime import datetime
import re
import openpyxl


class RegGet():
    def __init__(self, system, software, sam, security, ntuser):
        self.system_file = system
        self.software_file = software
        self.sam_file = sam
        self.security_file = security
        self.ntuser_file = ntuser

        self.software_reg = Registry.Registry(self.software_file)
        self.system_reg = Registry.Registry(self.system_file)
        self.sam_reg = Registry.Registry(self.sam_file)
        self.security_reg = Registry.Registry(self.security_file)
        self.ntuser_reg = Registry.Registry(self.ntuser_file)

        self.report_file = ""
        self.current_set = 0

    def main_menu(self):
        print("Welcome to RegGet!\n Enter the number corresponding to the menu option:")
        print("1) System info and accounts")
        print("2) Account analysis")
        print("3) External devices (USB)")
        print("4) Evidence of execution")
        while True:
            prompt = input("Choice: ")
            if prompt.isdigit():
                if prompt == "1":
                    self.sys_info()
                    break
                elif prompt == "2":
                    self.account_analysis()
                    break
                elif prompt == "3":
                    self.external_devices()
                    break
                elif prompt == "4":
                    self.execution_evidence()
                    break
                else:
                    print("Please enter a valid choice...")

            else:
                print("Please enter the numerical option that corresponds to what you want to view")

    def sys_info(self):
        """Gets system info and accounts"""

        print("")
        print("Welcome to the system & accounts menu!\nEnter a numerical option as done before:")
        print("1) Operating system information")
        print("2) Control sets")
        print("3) Time zone information")
        print("4) Network information")
        print("5) Accounts")
        print("6) Previous menu")

        while True:
            prompt = input("Choice: ")
            if prompt.isdigit():
                if prompt == "1":
                    current_ver_key = self.software_reg.open("Microsoft\\Windows NT\\CurrentVersion")
                    dos_install_date = current_ver_key['InstallDate']
                    converted_date = datetime.fromtimestamp(dos_install_date.value())
                    os_type = current_ver_key["ProductName"].value()
                    service_pack = current_ver_key["CSDVersion"].value()
                    organisation = current_ver_key["RegisteredOrganization"].value()
                    owner = current_ver_key["RegisteredOwner"].value()
                    computer_name = self.system_reg.open("ControlSet001\\Control\\ComputerName\\ComputerName")

                    print("")
                    print("OS information")
                    print("--------------")
                    print(f"OS type: {os_type}")
                    print(f"Computer name: {computer_name['ComputerName'].value()}")
                    print(f"Installed on: {converted_date}")
                    print(f"Service pack: {service_pack}")
                    print(f"Registered organisation: {organisation}")
                    print(f"Registered owner {owner}")
                    print("\n")

                elif prompt == "2":
                    print("")
                    control_path = self.system_reg.open("Select")
                    ctrl_set = control_path['Current'].value()
                    self.current_set = f"ControlSet00{ctrl_set}"
                    print(self.current_set)
                    print(f"Current control set: {control_path['Current'].value()}")
                    print(f"Default control set: {control_path['Default'].value()}")
                    print(f"Last known good set: {control_path['LastKnownGood'].value()}")
                    print("\n")

                elif prompt == "3":
                    timezone_path = self.system_reg.open("ControlSet001\\Control\\TimeZoneInformation")
                    print(f"Bias time: {timezone_path['Bias'].value()}")
                    print(f"Standard timezone: {timezone_path['StandardName'].value()}")
                    print(f"Daylight timezone: {timezone_path['DaylightName'].value()}")
                    print("\n")

                elif prompt == "4":
                    card_subkeys = []
                    network_key = self.software_reg.open("Microsoft\\Windows NT\\CurrentVersion\\NetworkCards")
                    for subkey in network_key.subkeys():
                        card_subkeys.append(subkey.name())

                    print("Network information")
                    print("-------------------")

                    for net_card in card_subkeys:
                        nic = self.software_reg.open(f"Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\{net_card}")
                        print(nic['Description'].value())

                    print("\n")

                elif prompt == "5":
                    username_key = self.sam_reg.open("SAM\\Domains\\Account\\Users\\Names")
                    user_accounts = []

                    for subkey in username_key.subkeys():
                        print(f"Account found: {subkey.name()}")
                        user_accounts.append(subkey.name())

                    print("\n")

                elif prompt == "6":
                    print("\n")
                    self.main_menu()
                    break

                else:
                    print("Please enter a valid choice...")

            else:
                print("Please enter the numerical option that corresponds to what you want to view")

    def account_analysis(self):
        acc = self.sam_reg.open("SAM\\Domains\\Account\\Users\\000003EF")
        str(acc["F"].value()).

    def external_devices(self):
        """Get information about any external devices connected to the system"""
        if self.current_set == 0:
            control_path = self.system_reg.open("Select")
            ctrl_set = control_path['Current'].value()
            self.current_set = f"ControlSet00{ctrl_set}"

        usbstor = self.system_reg.open(f"{self.current_set}\\Enum\\USBSTOR")

        vendor_keys = []
        vendor_dict = {}
        for subkey in usbstor.subkeys():
            vendor_keys.append(subkey.name())

        print("")
        print(f"{len(usbstor.subkeys())} USB devices were found")
        print("-------------------------------------------------------------------------")

        for usb in vendor_keys:
            vendor = self.system_reg.open(f"{self.current_set}\\Enum\\USBSTOR\\{usb}")
            for sub in vendor.subkeys():
                vendor_dict.update({usb: sub.name()})

        for key, val in vendor_dict.items():
            usb_device = self.system_reg.open(f"{self.current_set}\\Enum\\USBSTOR\\{key}\\{val}")
            print(f"Data for device '{key}'")
            print(f"Description: {usb_device['DeviceDesc'].value()}")
            print(f"GUID: {usb_device['ClassGUID'].value()}")
            print(f"Friendly name: {usb_device['FriendlyName'].value()}")
            print("")

    def execution_evidence(self):
        """Get evidence of execution by user"""
        pass


c = RegGet("system", "software", "Sam", "Security", "NTUSER.DAT")
c.main_menu()



