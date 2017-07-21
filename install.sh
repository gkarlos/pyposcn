#!/usr/bin/env bash

SYMLINK='ppsc'
LOCATION=$PWD

sudo echo '# added by Pyposcn installer ' >> $HOME/.bashrc
sudo echo export PYPOSCN_SYMLINK="$SYMLINK" >> $HOME/.bashrc
sudo echo export PYPOSCN_LOCATION="$LOCATION" >> $HOME/.bashrc

# create the run script
touch pyposcn.sh
printf "#!/usr/bin/env bash\n\n" >> ./pyposcn.sh
printf "#auto-generated script\n\n" >> ./pyposcn.sh
printf "python $LOCATION/pyposcn/pyposcn.py \$@" >> ./pyposcn.sh
chmod +x pyposcn.sh

#sudo sed -e "2 i LOC=$LOCATION" pyposcn.sh > pyposcn.sh.tmp \
#    && mv pyposcn.sh.tmp pyposcn.sh && chmod +x pyposcn.sh

sudo ln -sfn $(readlink -f "./pyposcn.sh") /usr/bin/ppsc



