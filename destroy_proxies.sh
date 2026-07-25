#!/bin/bash
# Tear down all pixieset-proxy Vultr instances (stop billing)
KEY="${VULTR_API_KEY:-EJSS7OXCXGGQFDTW6W5TPA6TFPLGXRTMIRAA}"
API="https://api.vultr.com/v2"
if [ -f .vultr_proxy_ids ]; then
  while read -r id region; do
    [ -z "$id" ] && continue
    echo "Destroying $id ($region)..."
    curl -s -X DELETE -H "Authorization: Bearer $KEY" "$API/instances/$id"
    echo " done"
  done < .vultr_proxy_ids
  rm -f .vultr_proxy_ids proxies.txt
else
  # fallback: destroy by label
  curl -s -H "Authorization: Bearer $KEY" "$API/instances?per_page=100" | python3 -c "
import sys,json,os,subprocess
key=os.environ.get('KEY','$KEY')
for i in json.load(sys.stdin).get('instances',[]):
    if i.get('label','').startswith('pixieset-proxy'):
        print('Destroying', i['id'], i.get('main_ip'))
        subprocess.run(['curl','-s','-X','DELETE','-H',f'Authorization: Bearer {key}', f'https://api.vultr.com/v2/instances/{i[\"id\"]}'])
"
fi
echo "All destroyed."
