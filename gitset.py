#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import config
import string
import shutil
from misc import syscommand, find_bin
from dsrLogger import logger as log
from packages import package_major_version, package_present
import random

config = config.Config()
git_bin = find_bin(bin_file='git')

def random_dir_name(length=15) -> str:
    """
    Generating random directory name
    :param length:      directory name length
    """
    letters = string.ascii_lowercase
    d_name = ''.join(random.choice(letters) for i in range(length))
    return d_name


def clone_tmux_tpm() -> None:
    """
    Cloning tmux plugin manager from git
    :return:
    """
    command = git_bin + " clone " + config.TMUX_TPM_PLUG_REPO + " " + config.TMUX_TPM_PLUG_DIR
    res = syscommand(command=command)
    if res:
        log.debug(res[0])
    else:
        log.info("Tmux plugin manager installed")



def get_from_git(repo_name: str, repo: str, git_file_name: str, local_file_path: str):
    """
    Get file from git repo and place it to specified path
    :param local_file_path:     full path of local file
    :param git_file_name:       name of cloned git file
    :param repo_name:           repository name
    :param repo:                http repository url
    """
    if git_bin is False:
        log.critical("git binary not found!")
        raise SystemExit
    else:
        try:
            dir_name = random_dir_name()
            git_repo = repo.replace("https://", "")
            command = git_bin + " clone https://" + config.GIT_USER + ":" + config.GIT_TOKEN + "@" + git_repo + " " + config.TMP_DIR + "/" + dir_name
            log.info("Cloning " + repo_name + " repo..")
            res = syscommand(command=command)
            if res:
                raise Exception(res[0])
            log.info("Making backup copy of current " + local_file_path)
            command = "yes | cp -rf " + local_file_path + " " + local_file_path + ".bak"
            syscommand(command=command)
            command = "yes | cp -rf " + config.TMP_DIR + "/" + dir_name + "/" + git_file_name + " " + local_file_path
            log.info("Replacing current " + local_file_path + " with " + git_file_name + " from git")
            syscommand(command=command)
            log.info("Removing temporary directory")
            shutil.rmtree(path=config.TMP_DIR + "/" + dir_name)
        except Exception as err:
            log.error(err)


def get_conf_form_git():
    if config.CLONE_BASHRC is True:
        get_from_git(repo_name='bashrc',
                     repo=config.BASHRC_HTTP_REPO,
                     git_file_name='.bashrc',
                     local_file_path='~/.bashrc')
    if config.CLONE_VIMRC is True:
        if package_present(package_name='vim') is not False:
            get_from_git(repo_name='vimrc',
                         repo=config.VIMRC_HTTP_REPO,
                         git_file_name='.vimrc',
                         local_file_path='~/.vimrc')
        else:
            log.warning("Package vim is not installed, skipping ...")
    if config.CLONE_TMUX_CONF is True:
        tmux_ver = package_major_version(package_name='tmux')
        if tmux_ver is not False:
            clone_tmux_tpm()
            get_from_git(repo_name='tmux_conf',
                         repo=config.TMUX_CONF_REPO,
                         git_file_name="tmux" + str(tmux_ver) + ".conf",
                         local_file_path='~/.tmux.conf')
        else:
            log.error("Package tmux is not installed, skipping ...")

if __name__ == '__main__':
    get_conf_form_git()


