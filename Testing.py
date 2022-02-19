import re
from Registry import Registry
from datetime import datetime, timedelta

system_reg = Registry.Registry('system')
software_reg = Registry.Registry('software')

acc_status = "01"
status = ""
if acc_status[0] == "0":
    status = status + "Account active and "
else:
    status = status + "Account inactive and "
if acc_status[1] == "0":
    status = status + "Password required"
else:
    status = status + "Password not set"

print(status)