# Build Instructions for Windows

To create a standalone `.exe` file for Windows, follow these steps:

1.  **Install Python**: Ensure Python is installed on your Windows machine.
2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    pip install pyinstaller
    ```
3.  **Build the Executable**:
    Run the following command in your terminal (Command Prompt or PowerShell):
    ```bash
    pyinstaller trello_downloader.spec
    ```
4.  **Locate the Exe**:
    The generated `.exe` file will be in the `dist` folder. It will be named `TrelloImageDownloader.exe`.

**Note**: Since you are currently on Linux, you cannot directly build a Windows `.exe` that runs reliably without using Wine or a Cross-Compiler, which can be complex. The best way is to copy this source code to a Windows machine and run the steps above.
