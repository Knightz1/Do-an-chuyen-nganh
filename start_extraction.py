import os

#files = os.listdir("E:\Dataset\Benign\Benign train")
files = os.listdir("E:\Dataset\Virus\Virus train\Mediyes")

cnt=0
file_name = []

for f in files:
    if ".EXE" in f:
        arg= f.replace(".EXE", "")
    else:
        arg= f.replace(".exe", "")
        
    print(arg)
    file_name.append(arg)
    #os.system(f'''idat64.exe -A -S"auto_extract.py E:\Dataset\Benign\extract_benign_train\{arg}" "E:\Dataset\Benign\Benign train\{f}"''')
    os.system(f'''idat64.exe -A -c -S"auto_extract.py E:\Dataset\Virus\extract_virus_train\{arg}" "E:\Dataset\Virus\Virus train\Mediyes\{f}"''')
    cnt +=1
    
    if cnt==300:
        break


#ff= open("E:\Dataset\Benign\data_name.txt", "w")
ff= open("E:\Dataset\Virus\data_name.txt", "w")
ff.write(str(file_name))
ff.close()