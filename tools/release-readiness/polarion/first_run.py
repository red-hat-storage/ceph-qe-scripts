import os

os.system("python3 -c 'import site; print(site.getsitepackages())' > temp.txt")
file = open("temp.txt", "r")

string_path = file.read()
string_path = string_path.replace("[", "")
string_path = string_path.replace("]", "")
string_path = string_path.split(",")[-1]
string_path = string_path.strip()
print(string_path)
string_path += "/pygsheets/"
os.system("cp replace_file/chart.py " + string_path + "chart.py")
print("Done!! ")
