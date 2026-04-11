Set objFSO = CreateObject("Scripting.FileSystemObject")
strPath = objFSO.GetParentFolderName(WScript.ScriptFullName)
Set WshShell = CreateObject("WScript.Shell")
' Số 0 nghĩa là ẩn cửa sổ, False nghĩa là không đợi script chạy xong
WshShell.Run "pythonw.exe """ & strPath & "\web application\setup_and_run.py"" integrate --collector-path """ & strPath & "\network_flow_collector_windows\network_flow_collector_windows.py""", 0, False
