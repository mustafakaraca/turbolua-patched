local current_folder = (...):gsub('%.init$', '')
return require(current_folder .. '.init')
