import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import os
import time


from CNNmodel import CNN_Model
# from MEC_A.MEC import MEC as mecA
# from MEC_B.MEC import MEC as mecB


# modelA = mecA.GetCNNmodel()
# modelB = mecB.GetCNNmodel()



class Server:
    def __init__(self, MECs):
        self.MECs = MECs
        self.global_model = CNN_Model(pkt_features=patterns_size)

        self.gen_1 = '/root/IOT_DDoS/MEC-topo/MECa/model.pth'
        self.gen_2 = '/root/IOT_DDoS/MEC-topo/MECb/model.pth'

        if not os.path.exists(self.gen_1):  
            os.makedirs(self.gen_1)
        if not os.path.exists(self.gen_2): 
            os.makedirs(self.gen_2)

        self.MECs[0].UpdateModel(self.gen_1) #loaded
        self.MECs[1].UpdateModel(self.gen_2) #loaded





    def aggregate(self):
        for mec in self.MECs:
            self.global_model.cnn1.weight += mec.cnn1.weight
            self.global_model.cnn1.bias   += mec.cnn1.bias

            self.global_model.cnn2.weight += mec.cnn2.weight
            self.global_model.cnn2.bias   += mec.cnn2.bias
            
            self.global_model.fc1.weight  += mec.fc1.weight
            self.global_model.fc1.bias    += mec.fc1.bias
                        
            self.global_model.fc2.weight  += mec.fc2.weight
            self.global_model.fc2.bias    += mec.fc2.bias
                        
            self.global_model.fc3.weight  += mec.fc3.weight
            self.global_model.fc3.bias    += mec.fc3.bias
                        
            self.global_model.fc4.weight  += mec.fc4.weight
            self.global_model.fc4.bias    += mec.fc4.bias


        for param in self.global_model.parameters():
            param.data /= len(self.clients)





    def federated_learning(self, rounds):
        for _ in range(rounds):
            self.aggregate()
        self.save_model()





    def save_model(self):
        torch.save(self.global_model.state_dict(), os.path.join(self.gen_1, 'global_model.pth'))
        torch.save(self.global_model.state_dict(), os.path.join(self.gen_2, 'global_model.pth'))




if __name__ == '__main__':
    num_MEC = 2     # number of MEC
    num_samples = 100   # Training Episode

    patterns_size = 4   # input dimensions

    modelA = CNN_Model(pkt_features=patterns_size)
    modelB = CNN_Model(pkt_features=patterns_size)

    # create server
    MECs = [modelA , modelB]
    server = Server(MECs)


    while 1 : 
        # feder lr
        rounds = 1

        for _ in range(num_samples) : 
            print(f'The Rounds : {rounds}')
            server.federated_learning(rounds=rounds)
            # time.sleep(interval)

        time.sleep(60.0)
