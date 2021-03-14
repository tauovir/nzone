sudo sysctl -w vm.drop_caches=3

sudo chmod -R 777 /var/www



==========Git stash perticular file=============
git stash push -m front_end_modified_files HLCAPP/appserver/hlc-app/src/app/components/create-assessment/create-assessment.component.ts
https://stackoverflow.com/questions/5506339/how-can-i-git-stash-a-specific-file



e->retun zip->downalo->move-unzip->script->moves->source_data->rbulidt_load->source

router
icd->crete-updte

xref->trigger->que tael


=================DOwnload file======
sudo wget http://media.sundog-soft.com/es7/shakes-mapping.json -P /home/nyalazone/Documents/test1/

sudo wget http://media.sundog-soft.com/es7/shakespeare_7.0.json -P /home/nyalazone/Documents/test1/


$ curl -s -XPOST http://127.0.0.1:9200/shakes101/_bulk --data-binary @home/nyalazone/Documents/test1/shakes-mapping.json

curl -XPOST 'http://127.0.0.1:9200/shakes101/_bulk' -d @/home/nyalazone/Documents/test1/shakes-mapping.json
curl -s -H "Content-Type: application/json" -XPOST localhost:9200/shakes101/_doc/_bulk?pretty --data-binary @home/nyalazone/Documents/test1/shakes-mapping.json


