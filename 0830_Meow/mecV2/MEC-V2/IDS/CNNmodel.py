import threading
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.autograd import Variable
# from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt





# Create CNN Model
class CNN_Model(nn.Module):
    def __init__(self , pkt_features , mask1=3 , mask2=3):
        super(CNN_Model, self).__init__()
        self.FinishTraining = False
        self.Finish_FedLR_Training = False

        '''--------------------------------CNNmodel Setting------------------------------------------------'''

        # Convolution 1 , Input Size : 1*pkt_features
        self.cnn1 = nn.Conv2d(in_channels=1, out_channels=16, kernel_size=(mask1,1), stride=1, padding=0) # Output Size : 16*(pkt_features-mask1+1)
        self.relu1 = nn.ReLU() # activation
        # Max pool 1
        self.maxpool1 = nn.MaxPool2d(kernel_size=2 , padding=1) # Output Size : 16*(pkt_features-2)/2

        # Convolution 2 , Input Size : 16*(pkt_features-mask1+1)/2
        self.cnn2 = nn.Conv2d(in_channels=16, out_channels=32, kernel_size=(mask2,1), stride=1, padding=0) # Output Size : 16*((pkt_features-mask1+1)/2)-mask2+1
        self.relu2 = nn.ReLU() # activation
        # Max pool 2
        self.maxpool2 = nn.MaxPool2d(kernel_size=2 , padding=1) # Output Size : 32*(((pkt_features-mask1+1)/2)-mask2+1)/2

        # Fully connected 1
        Size_AfterConv = int(((pkt_features-mask1+1)/2-mask2+1)/2)
        self.fc1 = nn.Linear(32 * Size_AfterConv * Size_AfterConv, 100)
        self.relu3 = nn.ReLU()  # activation
        # Fully connected 2
        self.fc2 = nn.Linear(100 , 100)
        self.relu4 = nn.ReLU()  # activation
        # Fully connected 3
        self.fc3 = nn.Linear(100 , 100)
        self.relu5 = nn.ReLU()
        # Fully 4
        self.fc4 = nn.Linear(100 , 2)

        '''------------------------------------------------------------------------------------------------------'''

        self.LearningRate = 0.01
        self.optimizer = torch.optim.Adam(self.parameters(), lr=self.LearningRate)
        self.LossFunction = nn.CrossEntropyLoss()

        '''------------------------------------------------------------------------------------------------------'''

        # self.TrainNetwork = None
        self.DataLoader = []
        self.TrainingEpisodes = 1000





    def forward(self, x):
        # Convolution 1
        out = self.cnn1(x)
        out = self.relu1(out)
        # Max pool 1
        out = self.maxpool1(out)

        # Convolution 2
        out = self.cnn2(out)
        out = self.relu2(out)
        # Max pool 2
        out = self.maxpool2(out)
        out = out.view(out.size(0), -1)

        # Fully connected 1
        out = self.fc1(out)
        out = F.relu(out)
        # Fully connected 2
        out = self.fc2(out)
        out = F.relu(out)
        # Fully connected 3
        out = self.fc3(out)
        out = F.relu(out)
        # Fully connected 4
        out = self.fc4(out)
        # out = F.softmax(out, dim=1)

        return out
    





    def TrainingModel(self , testing_model , test_dataloader=None) : 
        # self.TrainNetwork = self.copy()
        TrainingLoss = []
        TrainingAccuracy = []
        self.DataLoader = []

        total_train = correct_time = 0


        file_lock = threading.Lock()
        TrainingFile = 'IDS/TrainingList.txt'

        with file_lock : 
            with open(TrainingFile , 'r+') as file : 
                lines = file.readlines()
                NewContext = []

                for line in lines : 
                    patterns = line.split(' ')

                    role = patterns[0]

                    if role=='GOOD' : 
                        self.DataLoader.append((patterns[1:]) , 0)
                    elif role=='BAD' : 
                        self.DataLoader.append((patterns[1:]) , 1)

                file.write('')
                file.close()


        data_loader = test_dataloader
        if test_dataloader == None : 
            data_loader = self.DataLoader


        for round in range(self.TrainingEpisodes) : 
            for i , (pkt , label) in enumerate(data_loader) : 
                InputData = Variable(pkt)
                label = Variable(label)

                self.optimizer.zero_grad()

                output = self.forward(InputData)

                train_loss = self.LossFunction(output , label)

                train_loss.backward()

                self.optimizer.step()

                predicted = torch.max(output.data , 1)[1]

                total_train += 1
                correct_time += 1 if predicted==label else correct_time

            train_accuracy = 100 * correct_time / float(total_train)
            TrainingAccuracy.append(train_accuracy)
            TrainingLoss.append(train_loss.data)

            print(f'Round[{round}] - accu : {train_accuracy}\n')
        
        self.SaveModel()
        testing_model.FinishTraining = True




    def PredictModel(self , training_model) : 
        if self.FinishTraining : 
            self.UpdateModel()
            self.FinishTraining = False
        if self.Finish_FedLR_Training : 
            training_model.FedLearning()
            self.FedLearning()
            self.Finish_FedLR_Training = False


        DetectFile = 'IDS/record.txt'
        file_lock = threading.Lock()

        with file_lock : 
            with open(DetectFile , 'r+') as file : 
                Inputs = file.readlines()
                NewContext = Inputs.copy()

                for idx , Input in enumerate(Inputs) : 
                    patterns = Input.split(' ')
                    srcip = patterns[0]
                    InputData = np.array(patterns[1:])

                    output = self.forward(InputData)
                    predicted = torch.max(output.data , 1)[1]

                    if predicted : 
                        print(srcip, 'is detected')
                        '''
                        if predicted is 1 -> Block the IP
                        '''
                    else : 
                        reocrdfile = 'IPS/record.txt'
                        with open(reocrdfile , 'a+')as file :
                            file.write(Input + '\n')


                    NewContext.remove(idx)

                file.seek(0)
                file.truncate()
                file.writelines(NewContext)
                file.close()


    



    def SaveModel(self) : 
        torch.save(self.state_dict(), 'model.pth')





    def UpdateModel(self , pth='model.pth') : 
        self.load_state_dict(torch.load(pth))





    def FedLearning(self) : 
        fd_pth = '../models/global_model.pth'
        self.load_state_dict(torch.load(fd_pth))