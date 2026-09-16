"""The LSTM half of the pair: shapes, attention, and the width defect.

The README records a real fault — the model was built with input_dim=64 while
the preprocessor emitted 12 features, so every forward pass raised a shape
error. That is pinned here, along with the attention weights being a genuine
distribution and the output being a probability.
"""

import numpy as np
import pytest

torch = pytest.importorskip("torch")

from behavioral_model import BehavioralModel, LSTMAnomalyDetector, UserActivityDataset


SEQ_LEN, FEATURES, BATCH = 20, 12, 4


@pytest.fixture
def detector():
    return LSTMAnomalyDetector(input_dim=FEATURES, hidden_dim=32, num_layers=2)


def test_forward_returns_one_probability_per_sequence(detector):
    out = detector(torch.randn(BATCH, SEQ_LEN, FEATURES))
    assert out.shape == (BATCH, 1)
    assert torch.all((out >= 0) & (out <= 1)), "the head ends in a sigmoid"


def test_attention_weights_are_a_distribution_over_time(detector):
    lstm_out, _ = detector.lstm(torch.randn(BATCH, SEQ_LEN, FEATURES))
    weights = detector.attention(lstm_out)
    assert weights.shape == (BATCH, SEQ_LEN, 1)
    sums = weights.sum(dim=1).squeeze(-1)
    assert torch.allclose(sums, torch.ones(BATCH), atol=1e-5), \
        "softmax must be over time steps, not features"


def test_the_model_reads_the_whole_sequence(detector):
    """Changing an early step must change the answer, or attention is decorative."""
    x = torch.randn(1, SEQ_LEN, FEATURES)
    before = detector(x)
    x2 = x.clone()
    x2[0, 0, :] += 25.0
    assert not torch.allclose(before, detector(x2), atol=1e-6)


def test_a_single_layer_model_builds_without_a_dropout_warning():
    """dropout on a 1-layer LSTM is meaningless; the code guards for it."""
    model = LSTMAnomalyDetector(input_dim=FEATURES, hidden_dim=16, num_layers=1, dropout=0.3)
    assert model.lstm.dropout == 0
    assert model(torch.randn(2, 5, FEATURES)).shape == (2, 1)


def test_the_model_width_matches_the_features_the_pipeline_emits():
    """The defect the README describes: 64 in the model, 12 from the data."""
    behavioural = BehavioralModel()
    expected = len(behavioural.get_expected_columns())
    assert behavioural.input_dim == expected, \
        f"model built for {behavioural.input_dim} features, pipeline emits {expected}"
    # And it runs on data of that width.
    out = behavioural.model(torch.randn(2, 10, expected))
    assert out.shape == (2, 1)


def test_dataset_items_are_tensors_of_the_right_type():
    sequences = np.random.rand(6, SEQ_LEN, FEATURES).astype(np.float32)
    labels = np.array([0, 1, 0, 1, 1, 0], dtype=np.float32)

    dataset = UserActivityDataset(sequences, labels)

    assert len(dataset) == 6
    item = dataset[3]
    assert item["sequence"].shape == (SEQ_LEN, FEATURES)
    assert item["sequence"].dtype == torch.float32
    assert float(item["label"]) == 1.0


def test_an_unlabelled_dataset_yields_sequences_only():
    dataset = UserActivityDataset(np.random.rand(3, SEQ_LEN, FEATURES).astype(np.float32))
    assert "label" not in dataset[0]


def test_a_batch_from_the_dataset_feeds_the_model(detector):
    from torch.utils.data import DataLoader

    dataset = UserActivityDataset(np.random.rand(8, SEQ_LEN, FEATURES).astype(np.float32),
                                  np.zeros(8, dtype=np.float32))
    batch = next(iter(DataLoader(dataset, batch_size=4)))
    out = detector(batch["sequence"])
    assert out.shape == (4, 1)
