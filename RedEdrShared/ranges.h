#pragma once

#include <Windows.h>
#include <iostream>
#include <algorithm>
#include <vector>
#include <utility>

#include "logging.h"


class Range {
public:
    Range(uint64_t start, uint64_t end, void*data) : start_(start), end_(end), data_(data) {
        if (start_ > end_) std::swap(start_, end_);
    }

    bool contains(uint64_t value) const {
        return value >= start_ && value < end_;
    }

    bool overlaps(const Range& other) const {
        return start_ < other.end_ && end_ > other.start_;
    }

    Range intersect(const Range& other) const {
        if (!overlaps(other)) return { 0, 0, nullptr };
        return { (std::max)(start_, other.start_),
                 (std::min)(end_, other.end_), nullptr };
    }

    Range merge(const Range& other) const {
        if (!overlaps(other) && !is_adjacent(other)) return *this;  // Non-overlapping
        //return { std::min(start_, other.start_), std::max(end_, other.end_), NULL };
    }

    void print() const {
        //std::cout << "[" << start_ << ", " << end_ << ")";
        LOG_A(LOG_INFO, "  Start: %d  End: %d",
            start_, end_);
    }

    uint64_t start_;
    uint64_t end_;
    void* data_;

    bool is_adjacent(const Range& other) const {
        return end_ == other.start_ || start_ == other.end_;
    }
};


class RangeSet {
public:
    void add(const Range& range) {
        ranges_.push_back(range);
        //merge_overlapping();
    }

    BOOL contains(uint64_t value) const {
        for (const auto& range : ranges_) {
            if (range.contains(value)) {
                return TRUE;
            }
        }
        return FALSE;
    }

    const Range* get(uint64_t value) const {
        for (const auto& range : ranges_) {
            if (range.contains(value)) {
                return &range;
            }
        }
        return NULL;
    }

    RangeSet intersect(const RangeSet& other) const {
        RangeSet result;
        for (const auto& range1 : ranges_) {
            for (const auto& range2 : other.ranges_) {
                if (range1.overlaps(range2)) {
                    result.add(range1.intersect(range2));
                }
            }
        }
        return result;
    }

    void print() const {
        for (const auto& range : ranges_) {
            range.print();
        }
    }

    
    void ResetData() {
		ranges_.clear();
    }

    std::vector<Range> ranges_;

private:

    void merge_overlapping() {
        if (ranges_.empty()) return;

        std::sort(ranges_.begin(), ranges_.end(), [](const Range& a, const Range& b) {
            return a.start_ < b.start_;
            });

        std::vector<Range> merged;
        merged.push_back(ranges_[0]);

        for (size_t i = 1; i < ranges_.size(); ++i) {
            if (merged.back().overlaps(ranges_[i]) || merged.back().is_adjacent(ranges_[i])) {
                merged.back() = merged.back().merge(ranges_[i]);
            }
            else {
                merged.push_back(ranges_[i]);
            }
        }

        ranges_ = std::move(merged);
    }
};


