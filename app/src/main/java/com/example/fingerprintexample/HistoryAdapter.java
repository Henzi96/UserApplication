package com.example.fingerprintexample;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Filter;
import android.widget.Filterable;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.ArrayList;

public class HistoryAdapter extends RecyclerView.Adapter<HistoryAdapter.HitoryViewHolder> implements Filterable {
    private ArrayList<HistoryItem> historyList;
    private ArrayList<HistoryItem> historyListFull;




    public static class HitoryViewHolder extends RecyclerView.ViewHolder {
        public ImageView img_log_status;
        public TextView txt_log_date;
        public TextView txt_log_status;

        public HitoryViewHolder(View itemView) {
            super(itemView);
            img_log_status = itemView.findViewById(R.id.img_log_state);
            txt_log_date = itemView.findViewById(R.id.txt_log_date);
            txt_log_status = itemView.findViewById(R.id.txt_log_status);
        }
    }

    public HistoryAdapter(ArrayList<HistoryItem> historyList) {
        this.historyList = historyList;
        historyListFull = new ArrayList<>(historyList);
    }

    @NonNull
    @Override
    public HitoryViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.log_item, parent, false);
        HitoryViewHolder hitoryViewHolder = new HitoryViewHolder(v);
        return hitoryViewHolder;
    }

    @Override
    public void onBindViewHolder(HitoryViewHolder holder, int position) {
        HistoryItem currentHistoryLogItem = historyList.get(position);
        holder.img_log_status.setImageResource(currentHistoryLogItem.getImageLogStatus());
        holder.txt_log_status.setText(currentHistoryLogItem.getTxtLogStatus());
        holder.txt_log_date.setText(currentHistoryLogItem.getTxtLogDate());
    }

    @Override
    public int getItemCount() {
        return historyList.size();
    }

    @Override
    public Filter getFilter() {
        return historyFilter;
    }

    private Filter historyFilter = new Filter() {
        @Override
        protected FilterResults performFiltering(CharSequence constraint) {
            ArrayList<HistoryItem> filteredList = new ArrayList<>();
            if (constraint == null || constraint.length() == 0) {
                filteredList.addAll(historyListFull);
            } else {
                String filterPattern = constraint.toString().toLowerCase().trim();
                for (HistoryItem item : historyListFull) {
                    if (item.getTxtLogStatus().toLowerCase().contains(filterPattern)) {
                        filteredList.add(item);
                    }
                }
            }
            FilterResults results = new FilterResults();
            results.values = filteredList;
            return results;
        }

        @Override
        protected void publishResults(CharSequence constraint, FilterResults results) {
            historyList.clear();
            historyList.addAll((ArrayList) results.values);
            notifyDataSetChanged();
        }
    };
}
