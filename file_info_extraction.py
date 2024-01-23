

def Extraction (File):
    import os

    if ".EXE" in File:
        arg= File.replace(".EXE", "")
    else:
        arg= File.replace(".exe", "")
        
    ida_path = "D:\download\IDA7.5\idat64.exe"
    os.system(f'''{ida_path} -A -c -S"auto_extract.py E:\Dataset\Benign\info_file\{arg}" "{File}"''')

    #ff= open("E:\Dataset\Benign\data_name.txt", "w")
    print("[+] Extracting done")
    f_func = open(f"E:\Dataset\Benign\info_file\{arg}.func", "rb").read()
    f_api = open(f"E:\Dataset\Benign\info_file\{arg}.api", "rb").read()
    f_string = open(f"E:\Dataset\Benign\info_file\{arg}.string", "rb").read()



    func_data= eval(f_func)
    api_data = eval(f_api)
    string_data = eval(f_string)

    fcg=[]
    for f in func_data:
        if 'sub_ui' in f or "sub_path" in f or 'gtk_main_quit' in f or 'cairo_new_sub_path' in f:
            continue

        if func_data[f] ==[]:
            fcg.append((f, "None"))
        else:
            for f1 in func_data[f]:

                if 'sub_ui' in f1 or "sub_path" in f1 or 'gtk_main_quit' in f1 or 'cairo_new_sub_path' in f1:
                    continue

                if ";" in f1:
                    f1=f1.replace(f1[f1.index(';'):], "")
                fcg.append((f, f1))

    data_dict ={}


    data_dict['fcg'] = fcg
    data_dict['api'] = [api_data]
    data_dict['string']= [string_data]

    return data_dict

