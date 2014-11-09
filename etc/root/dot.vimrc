command Zap %s/[\xA0]/ /g
set colorcolumn=80
syntax on
set ts=8
set hls
set nu

autocmd BufReadPost *
  \ if ! exists("g:leave_my_cursor_position_alone") |
  \     if line("'\"") > 0 && line ("'\"") <= line("$") |
  \         exe "normal g'\"" |
  \     endif |
  \ endif
