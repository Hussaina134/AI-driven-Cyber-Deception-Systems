import numpy as np
import pickle
from pathlib import Path

class LinUCB:
    def __init__(self, actions, dim, alpha=0.8):
        self.actions = list(actions)
        self.dim = dim
        self.alpha = alpha
        self.A = {a: np.eye(dim) for a in self.actions}
        self.b = {a: np.zeros(dim) for a in self.actions}

    def _theta(self, a):
        return np.linalg.inv(self.A[a]).dot(self.b[a])

    def score(self, context_vec):
        res = {}
        for a in self.actions:
            Ainv = np.linalg.inv(self.A[a])
            theta = Ainv.dot(self.b[a])
            mean = float(np.dot(theta, context_vec))
            s = float(np.sqrt(context_vec.dot(Ainv).dot(context_vec)))
            ucb = mean + self.alpha * s
            res[a] = {"ucb": ucb, "pred": mean}
        return res

    def decide(self, context_vec):
        scores = self.score(context_vec)
        best = max(scores.items(), key=lambda kv: kv[1]["ucb"])[0]
        return best, scores

    def update(self, action, context_vec, reward):
        self.A[action] += np.outer(context_vec, context_vec)
        self.b[action] += reward * context_vec

    def save(self, path):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "wb") as f:
            pickle.dump(self, f)

    @staticmethod
    def load(path):
        with open(path, "rb") as f:
            return pickle.load(f)

