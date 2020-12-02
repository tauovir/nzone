
import pandas as pd;
class ExcelDataExplorer:

    def __init__(self,columns,type,prefix = None):
        self.prefix = prefix
        self.columns = columns
        self.type = type
        if self.prefix == None:
            self.prefix = "_dict_x"


    def explore_data(self,csv_file):
        data = pd.read_csv(csv_file)
        print(self.columns)
        filter_data = data[self.columns]
        for col in self.columns:
            pre_col = col + self.prefix
            self.columns.append(pre_col)
        filter_data['dict_x'] = ''
        dict_keys = {i: "" for i in self.columns}
        for index, row in filter_data.iterrows():
            data_dict = {key: row[key.split(self.prefix)[0]] for key in dict_keys.keys()}

            filter_data.at[index, 'dict_x'] = data_dict
        print(filter_data.head())

if __name__ == "__main__":
    dict = {
            "Name":"Rahul","Age":20,"City":"meerut"
            }
    obj = ExcelDataExplorer(['Name',"Age","City"],dict,"_redx")
    file_name = '/home/khan/Documents/data/temp_data3.csv'
    obj.explore_data(file_name)
