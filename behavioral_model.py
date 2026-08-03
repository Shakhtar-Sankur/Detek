import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import json
import os
import boto3
from datetime import datetime, timedelta

class UserActivityDataset(Dataset):
    def __init__(self, sequences, labels=None):
        self.sequences = sequences
        self.labels = labels

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        item = {'sequence': torch.tensor(self.sequences[idx], dtype=torch.float32)}

        if self.labels is not None:
            item['label'] = torch.tensor(self.labels[idx], dtype=torch.float32)

        return item

class LSTMAnomalyDetector(nn.Module):
    def __init__(self, input_dim, hidden_dim=128, num_layers=2, dropout=0.2):
        super(LSTMAnomalyDetector, self).__init__()

        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0
        )

        self.attention = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.Tanh(),
            nn.Linear(hidden_dim, 1),
            nn.Softmax(dim=1)
        )

        self.fc1 = nn.Linear(hidden_dim, 64)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(dropout)
        self.fc2 = nn.Linear(64, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        lstm_out, _ = self.lstm(x)
        attention_weights = self.attention(lstm_out)
        context_vector = torch.sum(attention_weights * lstm_out, dim=1)
        out = self.fc1(context_vector)
        out = self.relu(out)
        out = self.dropout(out)
        out = self.fc2(out)
        out = self.sigmoid(out)
        return out

class BehavioralModel:
    def __init__(self, model_path=None, input_dim=None, sequence_length=100):
        """`input_dim` defaults to the feature count the preprocessor actually emits.

        It used to default to 64 while `get_expected_columns()` returned 12, so the
        LSTM was built for a width the data never had and every forward pass raised
        a shape error. Deriving it removes the chance of the two drifting apart.
        """
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.input_dim = input_dim if input_dim is not None else len(self.get_expected_columns())
        self.sequence_length = sequence_length
        self.model = LSTMAnomalyDetector(self.input_dim)

        if model_path and os.path.exists(model_path):
            self.model.load_state_dict(torch.load(model_path, map_location=self.device))

        self.model.to(self.device)
        self.model.eval()

        self.feature_means = None
        self.feature_stds = None

    def preprocess_user_activities(self, activities):
        df = pd.DataFrame(activities)

        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
        df['hour'] = df['timestamp'].dt.hour / 24.0
        df['day_of_week'] = df['timestamp'].dt.dayofweek / 6.0

        action_dummies = pd.get_dummies(df['action'], prefix='action')
        resource_dummies = pd.get_dummies(df['resource_type'], prefix='resource')

        features = pd.concat([
            df[['hour', 'day_of_week', 'data_volume', 'duration']],
            action_dummies,
            resource_dummies
        ], axis=1)

        expected_columns = self.get_expected_columns()
        for col in expected_columns:
            if col not in features.columns:
                features[col] = 0

        # get_dummies returns bool columns in pandas 2.x; concatenating those with
        # the float columns yields an object-dtype frame, and torch.tensor then
        # refuses it with "can't convert np.ndarray of type numpy.object_".
        features = features[expected_columns].astype(np.float32)

        if self.feature_means is not None and self.feature_stds is not None:
            for i, col in enumerate(expected_columns):
                features[col] = (features[col] - self.feature_means[i]) / self.feature_stds[i]

        sequences = []
        for user_id in df['user_id'].unique():
            user_features = features[df['user_id'] == user_id].values

            if len(user_features) < self.sequence_length:
                padding = np.zeros((self.sequence_length - len(user_features), len(expected_columns)))
                user_sequence = np.vstack([padding, user_features])
            else:
                user_sequence = user_features[-self.sequence_length:]

            sequences.append(user_sequence)

        return np.array(sequences)

    def get_expected_columns(self):
        return [
            'hour', 'day_of_week', 'data_volume', 'duration',
            'action_read', 'action_write', 'action_delete', 'action_list',
            'resource_s3', 'resource_dynamodb', 'resource_rds', 'resource_ec2'
        ]

    def detect_anomalies(self, activities, threshold=0.8):
        sequences = self.preprocess_user_activities(activities)
        dataset = UserActivityDataset(sequences)
        dataloader = DataLoader(dataset, batch_size=32, shuffle=False)

        user_ids = list(pd.DataFrame(activities)['user_id'].unique())

        anomaly_scores = []

        self.model.eval()
        with torch.no_grad():
            for batch in dataloader:
                sequences = batch['sequence'].to(self.device)
                outputs = self.model(sequences)
                anomaly_scores.extend(outputs.cpu().numpy().flatten().tolist())

        results = {}
        for i, user_id in enumerate(user_ids):
            is_anomalous = anomaly_scores[i] >= threshold
            results[user_id] = {
                'score': anomaly_scores[i],
                'is_anomalous': is_anomalous
            }

        return results

    def train(self, normal_activities, anomalous_activities=None,
              epochs=10, batch_size=32, learning_rate=1e-4):
        """Fit the detector. Requires examples of both classes.

        With `anomalous_activities` empty every label is 0, and binary
        cross-entropy then drives the network to output 0 for everything — a model
        that reports "nothing is ever anomalous" and scores perfectly on its own
        training set. Detecting from normal traffic alone needs a different
        objective (reconstruction error or a one-class boundary), not this one.
        """
        if not anomalous_activities:
            raise ValueError(
                "train() needs anomalous_activities as well as normal ones. "
                "Training on a single class collapses the model to a constant 0. "
                "For normal-data-only detection, use a reconstruction or one-class "
                "objective instead of this supervised binary head."
            )

        # Statistics are recomputed below, so clear any existing ones first —
        # otherwise preprocess normalises with the old values and the block after
        # it normalises the already-normalised result a second time.
        self.feature_means = None
        self.feature_stds = None

        normal_sequences = self.preprocess_user_activities(normal_activities)
        normal_labels = np.zeros(len(normal_sequences))

        if anomalous_activities and len(anomalous_activities) > 0:
            anomalous_sequences = self.preprocess_user_activities(anomalous_activities)
            anomalous_labels = np.ones(len(anomalous_sequences))

            sequences = np.vstack([normal_sequences, anomalous_sequences])
            labels = np.concatenate([normal_labels, anomalous_labels])

            indices = np.random.permutation(len(sequences))
            sequences = sequences[indices]
            labels = labels[indices]
        else:
            sequences = normal_sequences
            labels = normal_labels

        flat_sequences = sequences.reshape(-1, sequences.shape[2])
        self.feature_means = np.mean(flat_sequences, axis=0)
        self.feature_stds = np.std(flat_sequences, axis=0) + 1e-8

        for i in range(sequences.shape[0]):
            for j in range(sequences.shape[1]):
                sequences[i, j] = (sequences[i, j] - self.feature_means) / self.feature_stds

        dataset = UserActivityDataset(sequences, labels)
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        self.model.train()
        optimizer = torch.optim.Adam(self.model.parameters(), lr=learning_rate)
        criterion = nn.BCELoss()

        history = {'loss': []}
        for epoch in range(epochs):
            epoch_loss = 0
            for batch in dataloader:
                optimizer.zero_grad()

                batch_sequences = batch['sequence'].to(self.device)
                batch_labels = batch['label'].to(self.device).view(-1, 1)

                outputs = self.model(batch_sequences)
                loss = criterion(outputs, batch_labels)

                loss.backward()
                optimizer.step()

                epoch_loss += loss.item()

            avg_loss = epoch_loss / len(dataloader)
            history['loss'].append(avg_loss)
            print(f'Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}')

        return history

    def save_model(self, path):
        torch.save(self.model.state_dict(), path)

        normalization_path = path + '.norm'
        with open(normalization_path, 'w') as f:
            json.dump({
                'means': self.feature_means.tolist() if self.feature_means is not None else None,
                'stds': self.feature_stds.tolist() if self.feature_stds is not None else None
            }, f)

    def load_model(self, path):
        self.model.load_state_dict(torch.load(path, map_location=self.device))
        self.model.eval()

        normalization_path = path + '.norm'
        if os.path.exists(normalization_path):
            with open(normalization_path, 'r') as f:
                params = json.load(f)
                self.feature_means = np.array(params['means']) if params['means'] else None
                self.feature_stds = np.array(params['stds']) if params['stds'] else None