# Dataset

The model is trained on the **Phishing Websites Dataset** by G. Vrbančič, I. Fister Jr. and V. Podgorelec
(*Datasets for phishing websites detection*, Data in Brief, vol. 33, 2020, doi:10.1016/j.dib.2020.106438).

- 88,647 URLs: 30,647 phishing and 58,000 legitimate
- 111 features per URL plus the target column `phishing` (0 = legit, 1 = phishing)
- source: Mendeley Data, https://data.mendeley.com/datasets/72ptz43s9v

Download `dataset_full.csv` and drop it here:

```
data/dataset_full.csv
```

The CSV is not versioned (about 24 MB). Only the trained model (`models/url_tree.joblib`, about 35 KB)
and the evaluation reports are committed.

Note: the dataset does not contain the URLs as text, only the numbers computed from them.
`-1` means "this part of the URL does not exist" or "the lookup failed", not minus one.
