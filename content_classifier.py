import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from transformers import BertTokenizer, BertModel
import json
import boto3
import os

class SensitiveContentDataset(Dataset):
    def __init__(self, texts, labels=None, tokenizer=None, max_length=512):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer if tokenizer else BertTokenizer.from_pretrained('bert-base-uncased')
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = str(self.texts[idx])

        encoding = self.tokenizer.encode_plus(
            text,
            add_special_tokens=True,
            max_length=self.max_length,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_tensors='pt'
        )

        item = {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten()
        }

        if self.labels is not None:
            item['labels'] = torch.tensor(self.labels[idx], dtype=torch.long)

        return item

class BERTClassifier(nn.Module):
    def __init__(self, n_classes=2, bert_model='bert-base-uncased', dropout_rate=0.3):
        super(BERTClassifier, self).__init__()

        self.bert = BertModel.from_pretrained(bert_model)
        self.dropout = nn.Dropout(dropout_rate)
        self.classifier = nn.Linear(self.bert.config.hidden_size, n_classes)

    def forward(self, input_ids, attention_mask):
        outputs = self.bert(
            input_ids=input_ids,
            attention_mask=attention_mask
        )

        pooled_output = outputs.pooler_output
        pooled_output = self.dropout(pooled_output)
        logits = self.classifier(pooled_output)

        return logits

class ContentClassifier:
    def __init__(self, model_path=None):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
        self.model = BERTClassifier()

        if model_path:
            self.model.load_state_dict(torch.load(model_path, map_location=self.device))

        self.model.to(self.device)
        self.model.eval()

        self.categories = {
            0: 'non_sensitive',
            1: 'pii',
            2: 'financial',
            3: 'health',
            4: 'credentials',
            5: 'intellectual_property'
        }

    def predict(self, texts, batch_size=32):
        if not isinstance(texts, list):
            texts = [texts]

        dataset = SensitiveContentDataset(texts, tokenizer=self.tokenizer)
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=False)

        predictions = []

        with torch.no_grad():
            for batch in dataloader:
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)

                outputs = self.model(input_ids, attention_mask)
                probs = torch.softmax(outputs, dim=1)

                for prob in probs:
                    category_id = torch.argmax(prob).item()
                    confidence = prob[category_id].item()

                    predictions.append({
                        'category': self.categories[category_id],
                        'category_id': category_id,
                        'confidence': confidence,
                        'is_sensitive': category_id > 0
                    })

        return predictions

    def train(self, train_texts, train_labels, val_texts=None, val_labels=None,
              epochs=3, batch_size=16, learning_rate=2e-5):
        train_dataset = SensitiveContentDataset(train_texts, train_labels, self.tokenizer)
        train_dataloader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

        if val_texts and val_labels:
            val_dataset = SensitiveContentDataset(val_texts, val_labels, self.tokenizer)
            val_dataloader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
        else:
            val_dataloader = None

        optimizer = torch.optim.AdamW(self.model.parameters(), lr=learning_rate)
        criterion = nn.CrossEntropyLoss()

        self.model.train()
        history = {'train_loss': [], 'train_acc': [], 'val_loss': [], 'val_acc': []}

        for epoch in range(epochs):
            train_loss = 0
            train_correct = 0
            train_total = 0

            for batch in train_dataloader:
                optimizer.zero_grad()

                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                labels = batch['labels'].to(self.device)

                outputs = self.model(input_ids, attention_mask)
                loss = criterion(outputs, labels)

                loss.backward()
                optimizer.step()

                train_loss += loss.item()
                _, predicted = torch.max(outputs, 1)
                train_total += labels.size(0)
                train_correct += (predicted == labels).sum().item()

            epoch_loss = train_loss / len(train_dataloader)
            epoch_acc = train_correct / train_total
            history['train_loss'].append(epoch_loss)
            history['train_acc'].append(epoch_acc)

            print(f'Epoch {epoch+1}/{epochs}, Train Loss: {epoch_loss:.4f}, Train Acc: {epoch_acc:.4f}')

            if val_dataloader:
                val_loss = 0
                val_correct = 0
                val_total = 0

                self.model.eval()
                with torch.no_grad():
                    for batch in val_dataloader:
                        input_ids = batch['input_ids'].to(self.device)
                        attention_mask = batch['attention_mask'].to(self.device)
                        labels = batch['labels'].to(self.device)

                        outputs = self.model(input_ids, attention_mask)
                        loss = criterion(outputs, labels)

                        val_loss += loss.item()
                        _, predicted = torch.max(outputs, 1)
                        val_total += labels.size(0)
                        val_correct += (predicted == labels).sum().item()

                epoch_val_loss = val_loss / len(val_dataloader)
                epoch_val_acc = val_correct / val_total
                history['val_loss'].append(epoch_val_loss)
                history['val_acc'].append(epoch_val_acc)

                print(f'Validation Loss: {epoch_val_loss:.4f}, Validation Acc: {epoch_val_acc:.4f}')

                self.model.train()

        return history

    def save_model(self, path):
        torch.save(self.model.state_dict(), path)

    def load_model(self, path):
        self.model.load_state_dict(torch.load(path, map_location=self.device))
        self.model.eval()