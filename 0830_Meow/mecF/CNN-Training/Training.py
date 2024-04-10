import os
import traceback
import numpy as np
import torch
from torch.autograd import Variable
from CNNmodel import CNN_Model

MEC_testing = CNN_Model(pkt_features=4)






ModelPath = './model.pth'

if os.path.exists(ModelPath) : 
    MEC_testing.UpdateModel(pth=ModelPath)
    print('Loading Successful')







data = """
good 29200,0,0,0 
good 58,0,0,0
good 58,0,0,0 
bad 58,1,1,100000000
good 29200,0,0,0  
good 58,0,0,0
good 58,0,0,0 
good 29200,0,0,0
bad 58,1,1,100000000
good 29200,0,0,0  
good 58,0,0,0
good 58,0,0,0 
good 29200,0,0,0
bad 58,1,1,100000000
good 29200,0,0,0  
good 58,0,0,0
good 58,0,0,0 
good 29200,0,0,0
bad 58,1,1,100000000
good 29200,0,0,0  
good 58,0,0,0
good 58,0,0,0 
good 29200,0,0,0
"""

lines = data.strip().split('\n')

result = []

for line in lines:
    label, numbers = line.split(' ', 1)
    numbers = [int(x) for x in numbers.split(',')]
    print(numbers)
    result.append([label, numbers])

TestingData = result







test_accuracy = 0.0
accuracy_time = 0
total_time    = 0


for label , patterns in TestingData : 
    pkt = np.array(patterns)
    pkt = np.array([np.array(item, dtype=np.float32) for item in pkt])
    # pkt = [[item] for item in pkt]
    
    pkt_tensor = torch.tensor(pkt)
    pkt_tensor = Variable(pkt_tensor.view(MEC_testing.input_shape))

    

    output = MEC_testing.forward(pkt_tensor)

    pkt_list = pkt.tolist()

    try : 
        levelA = 0.0001
        WindowSize_var = 10000
        output[0][1] += pkt_list[0]/WindowSize_var * levelA

        if pkt_list[1] >= 1 : 
            output[0][1] += 0.01
        else : 
            output[0][0] += 0.1

        if pkt_list[2] >= 1 : 
            output[0][1] += 0.01
        else : 
            output[0][0] += 0.1 


        if pkt_list[1] >= 1 and pkt_list[2] >= 1 : 
            output[0][1] += 0.3
        elif pkt_list[1] == 0 and pkt_list[2] == 0 : 
            output[0][0] += 0.3

        levelB = 0.01
        ContentLength_var = 1000
        output[0][1] += pkt_list[0]/ContentLength_var * levelB


        if output[0][0]>output[0][1] and label=='good' : 
            accuracy_time += 1
        elif output[0][0]<output[0][1] and label=='bad' :
            accuracy_time += 1

        print(f'label-pkt:{label,pkt} && Out:{output[0][0] , output[0][1]}' , '\n\n')

        total_time += 1
        test_accuracy = accuracy_time/total_time


    except Exception as e : 
        traceback_str = traceback.format_exc()
        print(f'Error Msg : {e}')
        print(f"Traceback: {traceback_str}")



print(f'Total Test Accuracy : {test_accuracy}')


