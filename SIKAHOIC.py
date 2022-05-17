from email.mime import text
from fileinput import filename
from logging import root
from msilib.schema import Font
from tkinter import *
from tkinter import filedialog
from tkinter import font
import pandas as pd
import numpy as np
import pickle
import timeit

#Mengambil fungsi dan variabel RF
rfModel = 'TM1K_n10.pkl'
filename = 'ids.log'
features = ['Init Bwd Win Byts','Dst Port','Fwd Pkt Len Max','Fwd Pkt Len Std','Fwd Seg Size Avg',
'Fwd Pkt Len Mean','ACK Flag Cnt','Pkt Len Mean','Pkt Len Max','Pkt Size Avg','PSH Flag Cnt',
'Pkt Len Std','Pkt Len Var','RST Flag Cnt','ECE Flag Cnt','Init Fwd Win Byts','Flow Byts/s',
'Bwd Seg Size Avg','Bwd Pkt Len Mean','Bwd Pkts/s','Tot Bwd Pkts','Subflow Bwd Pkts','Down/Up Ratio',
'Flow Pkts/s','Bwd Pkt Len Std','Bwd Header Len','Fwd Pkts/s','Bwd IAT Min','TotLen Bwd Pkts',
'Subflow Bwd Byts','Bwd Pkt Len Max','Bwd IAT Mean','Protocol','Flow Duration','Fwd IAT Tot',
'Fwd Seg Size Min','Idle Max','Fwd IAT Max','Flow IAT Max','Flow IAT Std','Fwd IAT Std','Idle Mean',
'Active Mean','Idle Std','Active Max','Subflow Fwd Byts','TotLen Fwd Pkts','Active Min','Fwd Header Len',
'Tot Fwd Pkts','Subflow Fwd Pkts','Fwd Act Data Pkts','Fwd IAT Mean','Flow IAT Mean','Idle Min',
'Pkt Len Min','Fwd Pkt Len Min','Active Std','Fwd IAT Min','Flow IAT Min','Bwd IAT Max','Bwd IAT Tot',
'URG Flag Cnt','SYN Flag Cnt','Fwd PSH Flags','Bwd IAT Std','Bwd Pkt Len Min','FIN Flag Cnt']

# Load Trained RF Model
with open(rfModel, 'rb') as file:
    model = pickle.load(file)
 
#Fungsi Prediksi dan Komponennya
def predict_tree(tree, X_test):
    feature_idx = tree['feature_idx']
    
    if X_test[feature_idx] <= tree['split_point']:
        if type(tree['left_split']) == dict:
            return predict_tree(tree['left_split'], X_test)
        else:
            value = tree['left_split']
            return value
    else:
        if type(tree['right_split']) == dict:
            return predict_tree(tree['right_split'], X_test)
        else:
            return tree['right_split']

def predict_rf(tree_ls, X_test):
    pred_ls = list()
    for i in range(len(X_test)):
        ensemble_preds = [predict_tree(tree, X_test.values[i]) for tree in tree_ls]
        final_pred = max(ensemble_preds, key = ensemble_preds.count)
        pred_ls.append(final_pred)
    return np.array(pred_ls)


#Membuat Tampilan dengan Tkinter
win=Tk()
win.title('SIKAHOIC - Sistem Klasifikasi DDoS HOIC')
win.geometry('1000x600')
win.resizable(False, False)

def prediksiRF():
    start = timeit.default_timer() # catat waktu mulai
    #Load data log
    dfRF = pd.read_csv(filename)
            
    #Memfilter dataframe berdasarkan fitur CFS untuk diprediksi
    dfTest = dfRF[features]
    dfAsli = dfRF['Label'].values
    lbRF.delete(0,END)
    lbRF.insert("end","No        Packet         Label Asli        Hasil Prediksi")

    #Memprediksi Hasil
    preds = predict_rf(model, dfTest)
    for x in range(len(preds)):
        prediksi = "DDOS HOIC" if preds[x] == 1 else "Benign"
        asli = "DDOS HOIC" if dfAsli[x] == "DDOS attack-HOIC" else "Benign"
        hasilTeks = str(x+1).ljust(10)+"{0:04}".format(x).ljust(15)+str(asli).ljust(18)+str(prediksi)
        lbRF.insert("end",hasilTeks)     
    stop = timeit.default_timer() # catat waktu selesai
    lama_eksekusi = stop - start # lama eksekusi dalam satuan detik
    label_waktu = Label(win,
                            text = "Lama eksekusi: "+str(round(lama_eksekusi,2))+" detik",
                            fg = "blue")
    label_waktu.place(x=510,y=50)
    win.after(2000, prediksiRF)   # the delay is in milliseconds


#Konfigurasi setiap komponen GUI.
button_explore = Button(win, 
                     text = "2. Read & Monitor Log File", 
                     command = prediksiRF, )
lbRF = Listbox(win, 
             width=60, 
             height=35,
             font=font.Font(family='Lucida Console', size = 10))
label_ddos = Label(win,
                            text = "Jumlah DDOS:",
                            fg = "blue")
textDDoS = Text(win, height=1, width=10)
textDDoS.insert('1.0', '0')
label_normal = Label(win,
                            text = "Jumlah Normal:",
                            fg = "blue")
textNormal = Text(win, height=1, width=10)
textNormal.insert('1.0', '0')
lbInjek = Listbox(win, 
             width=50, 
             height=35,
             font=font.Font(family='Lucida Console', size = 10))

def injekLog():
    #Membuat dataframe khusus untuk menampung hasil 'Benign'
    dfBenign = df.drop(df.index[(df['Label'] != 'Benign')],axis=0)
    #Membuat dataframe khusus untuk menampung hasil 'DDOS attack-HOIC'
    dfHoic= df.drop(df.index[(df['Label'] != 'DDOS attack-HOIC')],axis=0)
    print(textNormal)

    qtyBenign = int(textNormal.get("1.0","end-1c"))
    qtyHoic = int(textDDoS.get("1.0","end-1c"))

    #Menyimpan dataframe sesuai jumlah yang di inginkan
    dfBenignQTY = dfBenign.sample(n=qtyBenign)
    dfHoicQTY = dfHoic.sample(n=qtyHoic)

    #Menggabungkan dua dataframe dan mengacaknya.
    dfCombine=pd.concat([dfBenignQTY,dfHoicQTY])
    dfCombine=dfCombine.sample(frac=1)

    #Menyisipkan data ke ids.log
    dfCombine.to_csv('ids.log', mode='a', index=False, header=False)
    logs = "Penyisipan HOIC: "+str(qtyHoic)+" & Normal: "+str(qtyBenign) +" selesai ..."
    lbInjek.insert("end",logs)

button_save = Button(win, 
                     text = "1. Save to Log File", 
                     command = injekLog)

#Mengatur posisi tampilnya komponen GUI
label_ddos.place(x=10,y=10)
textDDoS.place(x=90,y=10)
label_normal.place(x=180,y=10)
textNormal.place(x=270,y=10)
button_save.place(x=10,y=40)
lbInjek.place(x=10,y=80)

button_explore.place(x=510,y=10)
lbRF.place(x=510,y=80)

#Mengambil fungsi Injector
lbInjek.insert("end",'Loading dataset CSE-CIC-IDS2018 02-21-2018.csv ....')
#Load dataset
df = pd.read_csv('02-21-2018.csv')
#Membuat file kosong dengan header atribut
dfFeature = df.sample(n=0)
dfFeature.to_csv('ids.log',index=False)
lbInjek.insert("end","Membuat file simulasi ids.log selesai...")
#Menghapus Row Nilai Y: 'DDOS attack-LOIC-UDP'
df.drop(df.index[(df['Label'] == 'DDOS attack-LOIC-UDP')],axis=0,inplace=True)



win.mainloop() 