<?php

class SmartRequire {
    private $root_dir;

    // Initiates the requirer
    // @param [string] $root_dir path which will be prepended to each loading file path
    public function __construct($root_dir = '') {
        $this->root_dir = $root_dir;
        if ($this->root_dir != '' && substr($this->root_dir, -1) != '/') {
            $this->root_dir .= '/';
        }
    }

    // Requires file from project root directory once
    // @param [string] $path the path to file which avail from project root directory
    public function once($path) {
        require_once($this->root_dir . $path);
    }

    // Requires all files from passed dir which correspond to passed suffix
    // @param [string] $dir the directory name from which files will be loaded
    // @param [string] $suffix of loading files
    public function all($dir, $suffix = '.php') {
        $files = scandir($this->root_dir . $dir);
        $suffix_length = strlen($suffix);

        foreach ($files as $file) {
            if ($file == '.' || $file == '..') continue;
            if (substr($file, strlen($file) - $suffix_length) != $suffix) continue;

            $this->once($dir . '/' . $file);
        }
    }
}

?>
