import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import os
import time


from MEC_A.MEC.IDS.CNNmodel import CNN_Model
from MEC_A.MEC import MEC as mecA
from MEC_B.MEC import MEC as mecB


modelA = mecA.GetCNNmodel()
modelB = mecB.GetCNNmodel()

patterns_size = 10


class Server:
    def __init__(self, clients):
        self.clients = clients
        self.global_model = CNN_Model(pkt_features=patterns_size)
        self.save_dir = './models/' 
        if not os.path.exists(self.save_dir):
            os.makedirs(self.save_dir)

    def aggregate(self):
        for client in self.clients:
            self.global_model.fc.weight += client.model.fc.weight
            self.global_model.fc.bias += client.model.fc.bias

        for param in self.global_model.parameters():
            param.data /= len(self.clients)

    def federated_learning(self, rounds):
        for _ in range(rounds):
            # for client in self.clients:
            #     client.train()
            self.aggregate()
            self.save_model()

    def save_model(self):
        torch.save(self.global_model.state_dict(), os.path.join(self.save_dir, 'global_model.pth'))




if __name__ == '__main__':
    num_clients = 2
    num_samples = 100

    # create server
    clients = [modelA , modelB]
    server = Server(clients)

    # feder lr
    rounds = 10
    interval = 5
    for _ in range(rounds):
        server.federated_learning(rounds=1)
        time.sleep(interval)
