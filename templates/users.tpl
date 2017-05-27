{if !empty($message)}<p>{$message}</p><br />{/if}
{$startform}
{if ($ucount > 0)}
{if !empty($hasnav)}<div class="browsenav">{$first}&nbsp;|&nbsp;{$prev}&nbsp;&lt;&gt;&nbsp;{$next}&nbsp;|&nbsp;{$last}&nbsp;({$pageof})&nbsp;&nbsp;{$rowchanger}</div>{/if}
<div style="overflow:auto;">
 <table id="userstable" class="{if $ucount > 1}table_sort {/if}leftwards pagetable">
  <thead><tr>
   <th>{$title_name}</th>
   <th>{$title_first}</th>
   <th>{$title_last}</th>
   <th class="{ldelim}sss:'icon'{rdelim}">{$title_addr}</th>
   <th class="{ldelim}sss:'icon'{rdelim}">{$title_reset}</th>
   <th class="{ldelim}sss:'icon'{rdelim}">{$title_active}</th>
   <th class="pageicon {ldelim}sss:false{rdelim}"></th>
{if $mod} <th class="pageicon {ldelim}sss:false{rdelim}"></th>
   <th class="pageicon {ldelim}sss:false{rdelim}"></th>
   <th class="checkbox {ldelim}sss:false{rdelim}" style="padding-left:6px;">{if !empty($header_checkbox)}{$header_checkbox}{/if}</th>{/if}
  </tr></thead>
  <tbody>
 {foreach from=$users item=entry} {cycle values='row1,row2' assign='rowclass'}
  <tr class="{$rowclass}" onmouseover="this.className='{$rowclass}hover';" onmouseout="this.className='{$rowclass}';">
   <td>{$entry->name}</td>
   <td>{$entry->reg}</td>
   <td>{$entry->last}</td>
   <td>{$entry->addr}</td>
   <td>{$entry->reset}</td>
   <td>{$entry->active}</td>
   <td>{$entry->see}</td>
{if $mod} <td>{$entry->edit}</td>
   <td class="linkdel">{$entry->del}</td>
   <td class="checkbox">{$entry->sel}</td>{/if}
  </tr>
 {/foreach}
  </tbody>
 </table>
</div>
{if !empty($hasnav)}<div class="browsenav">{$first}&nbsp;|&nbsp;{$prev}&nbsp;&lt;&gt;&nbsp;{$next}&nbsp;|&nbsp;{$last}</div>{/if}
{else}
 <p class="pageinput">{$nousers}</p>
{/if}
<div id="itemacts" class="pageoptions" style="margin-top:1em;">
{if $mod}{$iconlinkadd} {$textlinkadd}<span style="margin-left:8em;">{/if}
{$close}
{if $mod}{if ($ucount > 0)} {$reset} {$activate} {$delete} {/if}{$import}</span>{/if}
</div>
{$endform}
