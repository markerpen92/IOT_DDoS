import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.autograd import Variable
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt





# Create CNN Model
class CNN_Model(nn.Module):
    def __init__(self , pkt_features , mask1=3 , mask2=3):
        super(CNN_Model, self).__init__()

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
    





    def TrainingModel(self , data_loader , episode , test_dataloader=None) : 
        TrainingLoss = []
        TrainingAccuracy = []

        for round in range(episode) : 
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

    



    def SaveModelRecord(self) : 
        torch.save(self.state_dict(), 'model.pth')





    def UpdateModel(self , pth='model.pth') : 
        self.load_state_dict(torch.load(pth))