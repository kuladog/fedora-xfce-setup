#
# ~/.bash_profile
# 


# get aliases and functions
[[ -f ${HOME}/.bashrc ]] &&	. ${HOME}/.bashrc


# user environment paths
PATH="${PATH:+${PATH}:}${HOME}/.local/bin"
