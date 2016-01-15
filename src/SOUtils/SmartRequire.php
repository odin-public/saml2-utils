<?php

namespace SOUtils;

// The tool class for requiring PHP files in additional to original `require` and `require_once` mechanism
class SmartRequire {
    private $root_dir;

    // Initiates the requirer
    // @param [string] $root_dir path which will be prepended to each loading file path
    public function __construct($root_dir = '') {
        $this->root_dir = $this->fix_dir($root_dir);
    }

    // Requires file from project root directory once
    // @param [string] $file_path the path to file which avail from project root directory
    // @param [string] $suffix of loading files
    public function once($file_path, $suffix = '.php') {
        $full_path = $this->root_dir . $file_path;
        if (substr($file_path, strlen($file_path) - strlen($suffix)) != $suffix) {
            $full_path .= $suffix;
        }
        require_once($full_path);
    }

    // Requires all files from passed dir which correspond to passed suffix
    // @param [string] $dir_path the directory name from which files will be loaded
    // @param [string] $suffix of loading files
    public function all($dir_path, $suffix = '.php') {
        $fixed_dir_path = $this->fix_dir($dir_path);
        $files = scandir($this->root_dir . $fixed_dir_path);
        $suffix_length = strlen($suffix);
        $self_file_name = basename(__FILE__);

        foreach ($files as $file_name) {
            if ($file_name == '.' || $file_name == '..') continue;
            if (empty($fixed_dir_path) && $file_name == $self_file_name) continue;
            if (substr($file_name, strlen($file_name) - $suffix_length) != $suffix) continue;

            $this->once($fixed_dir_path . $file_name);
        }
    }

    // Fixes the directory path
    // @param [string] $dir_path which should be fixed
    // @return [string] the fixed path
    private function fix_dir($dir_path) {
        if (!empty($dir_path) && substr($dir_path, -1) != '/') {
            return $dir_path . '/';
        } else {
            return $dir_path;
        }
    }
}

?>
