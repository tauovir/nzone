
from Raptor.Leggero.Leggero_Data_File_V3 import LeggeroFile, LeggeroFileWrite
import pandas as pd
import copy
from Raptor.Leggero.Leggero_CXlsWriter import *
import json

class ExcelDataExplorer:

    def __init__(self,columns,type,prefix = None):
        self.prefix = prefix
        self.columns = columns
        self.type = type
        if self.prefix == None:
            self.prefix = "dict"


    def explore_data_dict(self,csv_file):
        records_list = []
        inf = LeggeroFile(csv_file, 'explorer', separator=',')
        header_dict = {x:ind for ind, x in enumerate(inf.headers)}
        new_header_dict = inf.headers
        new_header_dict.append(self.prefix+'json')
        print(new_header_dict)
        for rec in inf.raw_data():
            if len(rec) == (len(inf.headers) - 1):
                data_dict = {key:rec[val] for key,val in header_dict.items()}
                data_dict_prefix = {self.prefix + key:rec[val] for key,val in header_dict.items()}
                data_dict.update(data_dict_prefix)
                # print(data_dict)
                rec.append(json.dumps(data_dict))
                records_list.append(rec)
        for row1 in records_list:
            print(row1)
        
        
        
        writeXlRep("kls",new_header_dict,records_list)

    def explore_data_list(self, csv_file):
        records_list = []
        if self.type and len(self.columns) > 1:
            print("Only one column required")
            return "Only one column required"
        inf = LeggeroFile(csv_file, 'explorer', separator='#')
        header_dict = {x: ind for ind, x in enumerate(inf.headers)}
        print(inf.headers)
        print(header_dict)
        list_arr = []
        col_name = self.columns[0]
        # print(col_name)
        for rec in inf.raw_data():
            if len(rec) > 1:
                meta = rec[header_dict[col_name]]
                column,values = self._get_list_data(meta)
                print(column)
                print(values)

            print("==================************")
            # print(rec)
            if len(rec) > 1:
                for new_row in values:
                    print(new_row)
                    # rec.append(new_row)
                print(rec)

        print("=========99999999999999=========")
        # print(records_list)

    def _get_list_data(self,list_dict):
        column = []
        values = []
        list_dict = json.loads(list_dict)
        for row in list_dict:
            for key,val in row.items():
                column.append(key)
                values.append(val)

        # print("column:",list(set(column)))
        # print("values:", values)
        return list(set(column)),values








        # writeXlRep("data_dict", new_header_dict, records_list)

    def explote_list_object(self,csv_file):
        inf = LeggeroFile(csv_file, 'explorer', separator='$|$')
        selected_col = self.columns[0]
        print("selected_col:",selected_col)
        row_list = []
        for rec in inf.raw_data():
            if len(rec) > 1:
                row_list.append(rec)

        dataset1 = pd.DataFrame(row_list,columns=inf.headers)
        dataset = dataset1.head(20)
        list_dict = []
        for index, row in dataset.iterrows():
            meta = (row[selected_col])
            meta = eval(meta)

            flag = 0
            for row_dict in meta:
                meta_duct = {k: v for (k, v) in row_dict.items()}

                if flag == 0:
                    meta_duct.update({key: row[key] for key in dataset.columns.values if key != selected_col})

                else:
                    meta_duct.update({key: '' for key in dataset.columns.values if key != selected_col})

                list_dict.append(meta_duct)
                flag = 1

        final_result = pd.DataFrame(list_dict)
        final_cols = final_result.columns.values.tolist()
        final_records = final_result.values.tolist()
        # writeXlRep("excel_for", final_records, ['ENT_NAME','ent_number_cleaned'])
        final_result.to_excel("excel_for.xlsx")
        print("=======Process End========")




if __name__ == "__main__":
    dict = {
            "Name":"Rahul","Age":20,"City":"meerut"
            }
    # obj = ExcelDataExplorer(['Name',"Age","City"],dict,"redx_")
    file_name = '/home/khan/Documents/data/temp_data3.csv'
    file_name_arr = '/home/khan/Downloads/Set_A_Unclean_Fuzzy_Match.dsv'
    # obj.explore_data_dict(file_name)
    obj = ExcelDataExplorer(['Leg_RegName_Fuzzy_Match_CIPC'], dict, "redx_")
    obj.explote_list_object(file_name_arr)
