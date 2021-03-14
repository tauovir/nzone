====================Update json data==================


 UPDATE in_use.classification_extension SET extension_data = jsonb_set(cast(extension_data as jsonb), '{display_name}', '"HPCSA Professional Body Registration Board"', true)
	 where classification_value_id = 106466
	 and extension_data->>'display_name' ='Professional Body registration';
