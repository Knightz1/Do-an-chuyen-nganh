import numpy as np
import dgl
import torch
import torch.nn as nn
import random
import torch.nn.functional as F
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from torch.utils.data import DataLoader
from torch.utils.data.sampler import SubsetRandomSampler
from sklearn.preprocessing import StandardScaler
import sys


f_dataset = open("dataset_file.txt","rb").read()
dataset= eval(f_dataset)
#print(len(dataset))
graphs_list = []


for sample in dataset:

    function_calls=[]
    for call in sample['fcg']:
        function_calls.append(call)
    
    api_seq= sample['api'][0]
    api_seq.update({"None": []})


    node_mapping = {node: i for i, node in enumerate(set([src for src, _ in function_calls] + [dst for _, dst in function_calls]))}
    if  len(node_mapping) == 0:
        continue

    g = dgl.DGLGraph()
    src_indices, dst_indices = zip(*[(node_mapping[src], node_mapping[dst]) for src, dst in function_calls])


    for i in range(len(src_indices)):
        g.add_edges(src_indices[i], dst_indices[i]) # A -> B

    # >>> them string vao feature
    new_api_seq=[]
    for i in node_mapping:
        xx= (api_seq[i])
        if xx == []:
            new_api_seq.append("none")
        else:
            new_api_seq.append(" ".join(xx))

    # >>> tang kich thuoc vector len 100    

    top_api_features = ["NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory", "GetThread", "SetThread", "ResumeThread", "LoadLibraryA", "LoadLibraryExA", 'getlasterror', 'memset', '_cxxthrowexception', 'getprocaddress', 'closehandle', 'setlasterror', 'memmove', 'malloc', 'free', 'memcmp', 'tlsgetvalue', 'getcurrentprocess', 'memcpy', 'fclose', 'fflush', 'fputc', 'fputs', 'strlen', 'strcmp', 'fprintf', 'sprintf', 'exit', 'realloc', 'strcpy', 'printf', 'putc', 'atoi', 'strchr', 'strncmp', 'fwrite', 'fopen', 'strncpy', 'getenv', 'abort', '_errno', 'calloc', 'fread', 'ferror', 'sleep', 'setjmp', 'strstr', 'puts', 'strrchr', 'strerror', 'qsort', 'fgets', '_strdup', 'acquiresrwlockexclusive', 'releasesrwlockexclusive', '_invalid_parameter_noinfo_noreturn']
    top_string_features = ["KERNEL32.dll", "GetCurrentProcessId", "api-ms-win-crt-runtime-l1-1-0.dll", "!This program cannot be run in DOS mode.", "GetModuleHandleW", "LeaveCriticalSection", "UnregisterClassA", "EnterCriticalSection", "__CxxFrameHandler3", "memmove_s", "BackgroundTransferHost.pdb", "HeapReAlloc", "RaiseException", "user32.dll", "advapi32.dll", "shell32.dll", "wsock32.dll", "ole32.dll", "ws2_32.dll", "ntdll.dll", "wininet.dll", "urlmon.dll"]

    vectorizer = CountVectorizer(vocabulary=top_api_features)
    mapped_bow_features = vectorizer.transform(new_api_seq).toarray()
    #print(mapped_bow_features)

    g.ndata['features'] = torch.FloatTensor(mapped_bow_features)
    graphs_list.append(g)
    


Labels = [0]*60 + [1]*(len(graphs_list)-60)

train_g, test_g, train_labels, test_labels = train_test_split(graphs_list, Labels, test_size=0.2)
train_dataset = list(zip(train_g, train_labels))
test_dataset = list(zip(test_g, test_labels))

from dgl.dataloading import GraphDataLoader

train_loader = GraphDataLoader(train_dataset , batch_size=1, shuffle = True)
test_loader = GraphDataLoader(test_dataset , batch_size=1, shuffle = False)



from dgl.nn import GraphConv

class GCN(nn.Module):
    def __init__(self, in_feats, h_feats, num_classes):
        super(GCN, self).__init__()
        self.conv1 = GraphConv(in_feats, h_feats)
        self.conv2 = GraphConv(h_feats, num_classes)

    
    def forward(self, g1, in_feat):

        h = self.conv1(g1, in_feat)
        h = F.relu(h)
        h = self.conv2(g1, h)
        g1.ndata['h'] = h
        hg= dgl.mean_nodes(g1, 'h')
        return hg
        


    
# Initialize the GCN model
feat_dim = mapped_bow_features.shape[1]
hidden_size = 10
out_feats = 10
gcn_model = GCN(feat_dim, hidden_size, out_feats)#.to(torch.device('cpu'))

# Define the Adam optimizer
optimizer = torch.optim.Adam(gcn_model.parameters(), lr=0.01)

# Define the CrossEntropyLoss criterion
criterion = nn.CrossEntropyLoss()


def evaluate_new(dataloader, model):
    num_correct = 0
    num_tests = 0
    for batched_graph, labels in dataloader:
        batched_graph=dgl.add_self_loop(batched_graph)
        pred = model(batched_graph, batched_graph.ndata['features'].float())
        num_correct += (pred.argmax(1) == labels).sum().item()
        num_tests += len(labels)

    return num_correct / num_tests

# training loop 
for epoch in range(50):
    gcn_model.train()
    epoch_loss=0
    iter1=0
    for  batched_graph, lab in train_loader:
        batched_graph = dgl.add_self_loop(batched_graph)

        batched_graph=batched_graph.to(torch.device('cpu'))
        pred = gcn_model(batched_graph, batched_graph.ndata.pop('features').float())
         
        loss = F.cross_entropy(pred, lab)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        epoch_loss+=loss

        iter1+=1
    train_acc = evaluate_new(test_loader, gcn_model)
    print('Epoch {}, loss {:.4f}, Acc {:.4f}'.format(epoch, epoch_loss/(iter1+1), train_acc))


print("\n[+] Training completely")
print(f"[+] Train accuracy: {train_acc}")
print(f"[+] Analyzing {sys.argv[1]}...")


from file_info_extraction import Extraction

def predict_malicious(graph, model):
    model.train()
    with torch.no_grad():
        graph = dgl.add_self_loop(graph)
        outputs = model(graph, graph.ndata['features'].float())
        _, preds = torch.max(outputs, 1)
    return preds.item()

def process_file(File):
    sample = Extraction(File)

    function_calls=[]
    for call in sample['fcg']:
        function_calls.append(call)

    api_seq= sample['api'][0]
    api_seq.update({"None": []})

    node_mapping = {node: i for i, node in enumerate(set([src for src, _ in function_calls] + [dst for _, dst in function_calls]))}

    g = dgl.DGLGraph()
    src_indices, dst_indices = zip(*[(node_mapping[src], node_mapping[dst]) for src, dst in function_calls])
    zoo = random.uniform(0.5, 0.65)


    for i in range(len(src_indices)):
        g.add_edges(src_indices[i], dst_indices[i]) # A -> B

    new_api_seq=[]
    for i in node_mapping:
        xx= (api_seq[i])
        if xx == []:
            new_api_seq.append("none")
        else:
            new_api_seq.append(" ".join(xx))

    
    
    api_vectorizer = CountVectorizer(vocabulary=top_api_features)
    mapped_bow_features = api_vectorizer.transform(new_api_seq).toarray()

    g.ndata['features'] = torch.FloatTensor(mapped_bow_features)
    res= (predict_malicious(g, gcn_model))
    return res

print(f"{sys.argv[1]} -> {process_file(sys.argv[1])}")



