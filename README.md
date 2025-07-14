# Apple Activation Server Mimic

This project is a Python-based tool that mimics the behavior of Apple's activation servers for iOS devices. It's designed to help researchers and developers understand the activation process by providing a local server that can activate devices offline.

## Features

*   **Device Detection:** Automatically detects connected iOS devices via USB.
*   **Activation Record Generation:** Creates realistic activation records based on real device information.
*   **Local Activation:** Applies activation records to the device to complete the activation process locally.
*   **Cross-Platform:** Built with Python, making it compatible with various operating systems.

## How It Works

The `apple_mimic_activator.py` script is the core of this project. It uses the `pymobiledevice3` library to communicate with iOS devices. The activation process is as follows:

1.  **Device Connection:** The script establishes a connection with the device through the lockdown service.
2.  **Information Gathering:** It gathers essential device information, such as UDID, IMEI, and serial number.
3.  **Activation Record Creation:** A custom activation record is generated using the device's information.
4.  **Activation:** The generated record is sent to the device to complete the activation.

## Usage

To use this tool, you'll need to have Python 3 and `pymobiledevice3` installed.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/apple-activation-mimic.git
    ```
2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Run the script:**
    ```bash
    python apple_mimic_activator.py
    ```

## Disclaimer

This tool is for educational and research purposes only. The author is not responsible for any damage or legal issues that may arise from its use.
