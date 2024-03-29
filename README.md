## Dataset
Cả malware và benign đều được lấy từ [figshare](https://figshare.com/articles/dataset/Malware_Detection_PE-Based_Analysis_Using_Deep_Learning_Algorithm_Dataset/6635642?fbclid=IwAR2Ekh2yd325ORRiMPe4htkiSQZaxezGyqBlKMoGQTOEOMJ8FZP4cAON0Ys)

## Trình tự chạy script
### 1. API, string, FCG extraction
**Note:**
- Cần có IDA pro (nhóm sử dụng phiên bản 7.5) để chạy script `auto_extract.py` và `start_extraction.py` , 2 file này cần đặt cùng thư mục với `thư mục chứa IDA pro` mới có thể chạy được.  
- Sửa lại đường dẫn đến tập dataset và nơi lưu file hợp với mục đích sử dụng.

Chạy file `start_extraction.py` sẽ tự động gọi file `auto_extract.py` nên chỉ cần chạy file `auto_extract.py` là đủ.  

### 2. Xử lí dữ liệu
Script `manipulate_data.py` xử lí dữ liệu từ kết quả của script `auto_extract.py`, chuyển thành format phù hợp và lưu toàn bộ vào file `dataset_file.txt`, lưu ý sửa lại các đường dẫn trong script cho phù hợp.

### 3. Random forest 
Chạy script `random_forest.py` để lấy api và string được sử dụng nhiều nhât, chạy script minh họa thôi vì kết quả có sẵn trong file `training` luôn.

### 4. Adversarial samples generation
- Mã nguồn mã độc: https://github.com/ytisf/theZoo/tree/master/malware/Source
- Tool: https://github.com/weak1337/Alcatraz

### 5. Training
Chạy script `training.py` với tham số đầu vào là tên file cần dự đoán mức độ độc hại, script sẽ bắt đầu train model và đưa ra kết quả dự đoán.
- Note: script `training.py` khi chạy sẽ gọi script `file_info_extraction.py` nên cần đổi đường dẫn trong file đó lại cho phù hợp.

