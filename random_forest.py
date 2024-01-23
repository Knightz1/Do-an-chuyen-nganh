from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
import numpy as np

f_dataset = open("dataset_file.txt", "rb").read()
dataset = eval(f_dataset)

string_data=[]
api_data=[]

for sample in dataset:
    api = sample['api'][0]
    for xx in api:
        if api[xx] !=[]:
            api_data.append(api[xx])


# for sample in dataset:
#     string = sample['string'][0]
#     for xx in string:
#         temp_string_data=[]
#         if string[xx] !=[]:         
#             for st in string[xx]:
#                 st= str(st)
#                 st=st.replace(st[0:2], '')
#                 st=st.replace(st[-1], '')
#                 st= st.replace('\\x00', '')
#                 #print(st)
#                 if '\\x' not in st and "WARNINGS" not in st and "ERROR" not in st and ":" not in st and "*" not in st and ">" not in st and "<" not in st and "\\" not in st and "/" not in st and "=" not in st and "%" not in st and "(" not in st and ")" not in st and "unknown" not in st and "error" not in st and "invalid" not in st:   
#                     temp_string_data.append(st)
#             string_data.append(temp_string_data)

#print(string_data)

vectorizer = CountVectorizer()
X = vectorizer.fit_transform([' '.join(lst) for lst in api_data])
y = np.arange(len(api_data))

# Khởi tạo và huấn luyện mô hình Random Forest
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X, y)

# Lấy đặc trưng quan trọng từ mô hình
feature_importances = rf_model.feature_importances_

# Xác định 10 từ được sử dụng nhiều nhất
top_10_indices = feature_importances.argsort()[-50:][::-1]
top_10_words = [word for word, index in vectorizer.vocabulary_.items() if index in top_10_indices]

# In ra 10 từ được sử dụng nhiều nhất
print("Top words:", top_10_words)
