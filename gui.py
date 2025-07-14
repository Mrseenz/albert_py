import tkinter as tk
from tkinter import filedialog
from generate_activation_record import generate_activation_record
import plistlib

def select_file():
    file_path = filedialog.askopenfilename()
    input_entry.delete(0, tk.END)
    input_entry.insert(0, file_path)

def generate():
    input_path = input_entry.get()
    output_path = "activation_record.plist"

    with open(input_path, 'r') as f:
        activation_info_raw = f.read()

    import re
    match = re.search(r'<data>([\s\S]*?)<\/data>', activation_info_raw)
    if not match:
        raise ValueError("Could not find plist in activation info")

    # The data is base64 encoded
    activation_info_plist = base64.b64decode(match.group(1))

    activation_info = plistlib.loads(activation_info_plist)

    device_info = {
        'UniqueDeviceID': activation_info['DeviceID']['UniqueDeviceID'],
        'IMEI': activation_info['BasebandRequestInfo']['InternationalMobileEquipmentIdentity'],
        'MEID': activation_info['BasebandRequestInfo']['MobileEquipmentIdentifier'],
        'SerialNumber': activation_info['DeviceID']['SerialNumber'],
        'ProductType': activation_info['DeviceInfo']['ProductType'],
        'ICCID': activation_info['BasebandRequestInfo']['IntegratedCircuitCardIdentity']
    }

    activation_record = generate_activation_record(device_info)

    with open(output_path, 'wb') as f:
        plistlib.dump(activation_record, f)

    result_label.config(text=f"✅ Activation record generated and saved to {output_path}")


root = tk.Tk()
root.title("Activation Record Generator")

frame = tk.Frame(root, padx=10, pady=10)
frame.pack(padx=10, pady=10)

input_label = tk.Label(frame, text="Input File:")
input_label.grid(row=0, column=0, sticky="w")

input_entry = tk.Entry(frame, width=50)
input_entry.grid(row=0, column=1, padx=5)

browse_button = tk.Button(frame, text="Browse", command=select_file)
browse_button.grid(row=0, column=2)

generate_button = tk.Button(frame, text="Generate", command=generate)
generate_button.grid(row=1, column=1, pady=10)

result_label = tk.Label(frame, text="")
result_label.grid(row=2, column=0, columnspan=3)

root.mainloop()
